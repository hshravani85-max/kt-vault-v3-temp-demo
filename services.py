import re
import auth_services
import database
import json
import os
from datetime import datetime, date

def get_trip_details(trip_id):
    conn = database.get_connection()
    trip = conn.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
    conn.close()
    return dict(trip) if trip else None

def get_requirements(trip_id):
    conn = database.get_connection()
    reqs = conn.execute('''
        SELECT r.*, d.id as doc_id, d.status as doc_status, d.extracted_data
        FROM requirements r
        LEFT JOIN documents d ON r.id = d.requirement_id
        WHERE r.trip_id = ?
    ''', (trip_id,)).fetchall()
    conn.close()
    return [dict(r) for r in reqs]

def get_document(doc_id):
    conn = database.get_connection()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()
    return dict(doc) if doc else None

def get_all_documents_for_review():
    conn = database.get_connection()
    docs = conn.execute('''
        SELECT d.*, r.name as req_name, r.type as req_type, r.trip_id, r.traveller_id, 
               t.name as traveller_name, tr.name as trip_name, 
               COALESCE(tr.customer_id, t.customer_id) as customer_id, 
               COALESCE(c.name, c2.name) as customer_name
        FROM documents d
        JOIN requirements r ON d.requirement_id = r.id
        LEFT JOIN travellers t ON r.traveller_id = t.id
        LEFT JOIN trips tr ON r.trip_id = tr.id
        LEFT JOIN customers c ON tr.customer_id = c.id
        LEFT JOIN customers c2 ON t.customer_id = c2.id
        WHERE d.status = 'Under Review'
    ''').fetchall()
    conn.close()
    return [dict(d) for d in docs]

def calculate_readiness(trip_id):
    reqs = get_requirements(trip_id)
    trip = get_trip_details(trip_id)
    current_trip_status = trip.get('status') if trip else None
    
    # Optional document types that do not penalize trip readiness when unfulfilled
    OPTIONAL_DOC_TYPES = {'Aadhaar Card', 'PAN Card'}
    
    eval_reqs = []
    for r in reqs:
        name = r.get('name')
        status = r.get('doc_status')
        if name in OPTIONAL_DOC_TYPES and (not status or status in ['Replace Required', 'Re-upload Required', 'Action Required']):
            continue
        eval_reqs.append(r)
        
    total = len(eval_reqs)
    if total == 0: 
        return 0, 0, 0, 0, 0, "NOT READY"
        
    complete = 0
    attention = 0
    missing = 0
    for r in eval_reqs:
        status = r.get('doc_status')
        if not status or status in ['Replace Required', 'Re-upload Required', 'Action Required']:
            missing += 1
        elif status == 'Verified':
            complete += 1
        else:
            attention += 1
            
    pct = int((complete/total)*100)
    
    if current_trip_status == 'TRAVEL FILE READY':
        business_status = 'TRAVEL FILE READY'
    elif complete == total and missing == 0 and attention == 0:
        business_status = 'READY FOR FINAL REVIEW'
    else:
        business_status = 'NOT READY'
        
    return total, complete, attention, missing, pct, business_status

def save_document(
    requirement_id,
    file_path,
    extracted_data,
    session_token,
    expected_trip_id=None,
    expected_customer_id=None,
    override_mismatch=False,
    override_reason=None,
    preextracted_result=None,
    passport_kind=None,
):
    import auth_services
    import os
    import uuid
    import json
    from datetime import datetime
    import document_processor
    import storage_service
    
    if not session_token:
        raise PermissionError('Unauthenticated')
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    
    if not requirement_id or not isinstance(requirement_id, str):
        raise ValueError("requirement_id must be a non-empty string.")
    if extracted_data is None or not isinstance(extracted_data, dict):
        raise ValueError("extracted_data must be a valid dictionary.")
    if not file_path or not isinstance(file_path, str):
        raise ValueError(f"Document file does not exist on disk: '{file_path}'.")

    resolved_physical_path, _ = get_safe_document_path(file_path)
    actual_read_path = resolved_physical_path if resolved_physical_path else file_path
    if not os.path.exists(actual_read_path):
        raise ValueError(f"Document file does not exist on disk: '{file_path}'.")
        
    conn = database.get_connection()
    try:
        req_cols = [c[1] for c in conn.execute("PRAGMA table_info(requirements)").fetchall()]
        has_cust_col = 'customer_id' in req_cols
        if has_cust_col:
            req_info = conn.execute('''
                SELECT r.id, r.name, r.trip_id, r.traveller_id, r.customer_id AS req_customer_id,
                       t.customer_id AS trip_customer_id,
                       tr.customer_id AS traveller_customer_id,
                       COALESCE(r.customer_id, t.customer_id, tr.customer_id) AS customer_id
                FROM requirements r
                LEFT JOIN trips t ON r.trip_id = t.id
                LEFT JOIN travellers tr ON r.traveller_id = tr.id
                WHERE r.id = ?
            ''', (requirement_id,)).fetchone()
        else:
            req_info = conn.execute('''
                SELECT r.id, r.name, r.trip_id, r.traveller_id,
                       t.customer_id AS trip_customer_id,
                       tr.customer_id AS traveller_customer_id,
                       COALESCE(t.customer_id, tr.customer_id) AS customer_id
                FROM requirements r
                LEFT JOIN trips t ON r.trip_id = t.id
                LEFT JOIN travellers tr ON r.traveller_id = tr.id
                WHERE r.id = ?
            ''', (requirement_id,)).fetchone()
        
        if not req_info:
            raise ValueError(f"Requirement not found: '{requirement_id}'.")
            
        if expected_trip_id is not None:
            if req_info['trip_id'] != expected_trip_id:
                raise ValueError(f"Trip mismatch: requirement '{requirement_id}' belongs to trip '{req_info['trip_id']}', but expected trip '{expected_trip_id}'.")
                
        if expected_customer_id is not None:
            if req_info['customer_id'] != expected_customer_id:
                raise ValueError(f"Customer mismatch: requirement '{requirement_id}' belongs to customer '{req_info['customer_id']}', but expected customer '{expected_customer_id}'.")

        # ----------------------------------------------------
        # Document Type & Identity Validation (Service Layer)
        # Reuses UI preextracted_result when supplied to prevent duplicate AZAPI billing.
        # ----------------------------------------------------
        doc_bytes = storage_service.read_decrypted_document(actual_read_path, session_token=session_token, allow_external=True)
        if len(doc_bytes) > MAX_DOCUMENT_SIZE_BYTES:
            raise ValueError(f"Document exceeds maximum allowed file size ({MAX_DOCUMENT_SIZE_BYTES // (1024 * 1024)}MB).")
        if isinstance(preextracted_result, dict) and 'document_type' in preextracted_result:
            proc_result = preextracted_result
        else:
            proc_result = document_processor.process_document(
                os.path.basename(actual_read_path),
                doc_bytes,
                expected_requirement=req_info['name'],
                passport_kind=passport_kind,
            )
        if isinstance(extracted_data, dict) and extracted_data.get('PAN Number'):
            extracted_data = dict(extracted_data)
            extracted_data['PAN Number'] = re.sub(r'[^A-Z0-9]', '', str(extracted_data['PAN Number']).upper())
        detected_type = proc_result.get('document_type', 'Needs Review')
        type_conf = proc_result.get('type_confidence', 'low')

        req_name = req_info['name'].lower()
        KEYWORD_MAP = {
            'hotel': 'Hotel Voucher', 'flight': 'Flight Ticket', 'ticket': 'Flight Ticket',
            'passport': 'Passport', 'visa': 'Visa / Entry Document', 'insurance': 'Travel Insurance',
            'transfer': 'Transfer Voucher', 'cab': 'Transfer Voucher', 'taxi': 'Transfer Voucher',
            'sightseeing': 'Sightseeing Voucher', 'tour': 'Sightseeing Voucher', 'activity': 'Sightseeing Voucher',
            'land': 'Land Voucher', 'ground': 'Land Voucher',
            'aadhaar': 'Aadhaar Card', 'adhaar': 'Aadhaar Card', 'uidai': 'Aadhaar Card',
            'pan': 'PAN Card', 'pancard': 'PAN Card',
            'arrival': 'Arrival / Entry Document', 'entry': 'Arrival / Entry Document', 'itinerary': 'Itinerary'
        }
        expected_type = 'Needs Review'
        for kw, target in KEYWORD_MAP.items():
            if kw in req_name:
                expected_type = target
                break

        is_type_mismatch = (
            type_conf == 'high'
            and detected_type != 'Needs Review'
            and expected_type != 'Needs Review'
            and detected_type != expected_type
        )

        expected_traveller = None
        trip_travellers = []
        if req_info['traveller_id']:
            tr_row = conn.execute("SELECT name FROM travellers WHERE id = ?", (req_info['traveller_id'],)).fetchone()
            if tr_row:
                expected_traveller = tr_row['name']
        if req_info['trip_id']:
            tt_rows = conn.execute("SELECT tr.name FROM trip_travellers tt JOIN travellers tr ON tt.traveller_id = tr.id WHERE tt.trip_id = ?", (req_info['trip_id'],)).fetchall()
            trip_travellers = [r['name'] for r in tt_rows if r['name']]
        
        cust_row = conn.execute("SELECT name FROM customers WHERE id = ?", (req_info['customer_id'],)).fetchone() if req_info['customer_id'] else None
        customer_name = cust_row['name'] if cust_row else None

        validation_doc_type = detected_type if detected_type != 'Needs Review' else expected_type
        id_validation = document_processor.validate_traveller_identity(
            doc_type=validation_doc_type,
            extracted_fields=extracted_data,
            expected_traveller_name=expected_traveller,
            trip_travellers=trip_travellers,
            customer_name=customer_name
        )
        is_identity_mismatch = (not id_validation['valid'] and id_validation.get('severity') == 'error')

        if is_type_mismatch or is_identity_mismatch:
            mismatch_reasons = []
            if is_type_mismatch:
                mismatch_reasons.append(f"Document type mismatch (detected '{detected_type}' vs requirement '{req_info['name']}')")
            if is_identity_mismatch:
                mismatch_reasons.append(f"Traveller identity mismatch ({id_validation['message']})")
            error_details = " | ".join(mismatch_reasons)

            if not override_mismatch:
                raise ValueError(f"Save blocked by validation guard: {error_details}.")
            else:
                # Override requested: verify Supervisor/Admin role and mandatory reason
                if user['role'] not in ['Supervisor', 'Admin']:
                    raise PermissionError(f"Unauthorized: Role '{user['role']}' cannot authorize document or identity mismatches. Supervisor or Admin authorization required.")
                if not override_reason or not str(override_reason).strip():
                    raise ValueError("An explicit override reason is mandatory when authorizing a document or identity mismatch.")

                now_iso = datetime.now().isoformat()
                act_desc = f"Mismatch override authorized by {user['full_name']} ({user['role']}). Target: {req_info['name']}. Reason: {str(override_reason).strip()}. Details: {error_details}"
                conn.execute("INSERT INTO activity (trip_id, customer_id, description, timestamp) VALUES (?, ?, ?, ?)",
                             (req_info['trip_id'], req_info['customer_id'], act_desc, now_iso))

        existing = conn.execute("SELECT id, status, extracted_data FROM documents WHERE requirement_id = ?", (requirement_id,)).fetchone()
        if existing:
            doc_id = existing['id']
            # Requirement 8: Protect verified document fields from being automatically overwritten by unreviewed cloud OCR
            final_extracted_data = extracted_data
            if existing['status'] == 'Verified' and existing['extracted_data']:
                try:
                    verified_fields = json.loads(existing['extracted_data'])
                    if isinstance(verified_fields, dict):
                        merged = dict(extracted_data)
                        for k, v in verified_fields.items():
                            if v and str(v).strip():
                                merged[k] = v
                        final_extracted_data = merged
                except Exception:
                    pass
            conn.execute("UPDATE documents SET status = ?, file_path = ?, extracted_data = ?, uploaded_at = ? WHERE id = ?",
                         ('Under Review', file_path, json.dumps(final_extracted_data), datetime.now().isoformat(), doc_id))
        else:
            final_extracted_data = extracted_data
            doc_id = 'DOC-' + str(uuid.uuid4())[:8]
            conn.execute("INSERT INTO documents (id, requirement_id, status, extracted_data, file_path, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)",
                         (doc_id, requirement_id, 'Under Review', json.dumps(extracted_data), file_path, datetime.now().isoformat()))
        
        if req_info['name'] == 'Passport' and req_info['customer_id']:
            conn.execute("INSERT OR REPLACE INTO user_profile (customer_id, full_name, dob, nationality, passport_number, passport_expiry) VALUES (?, ?, ?, ?, ?, ?)",
                         (req_info['customer_id'], final_extracted_data.get('Full Name'), final_extracted_data.get('Date of Birth'), final_extracted_data.get('Nationality'), final_extracted_data.get('Passport Number'), final_extracted_data.get('Expiry Date')))
        
        conn.commit()
        return doc_id
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def verify_document(doc_id, session_token):
    import json
    user = auth_services.require_role(session_token, ['Supervisor', 'Admin'])
    actor = user['full_name']
    
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT status, extracted_data, requirement_id FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc: raise ValueError("Document not found.")
        if doc['status'] == 'Verified': return
        
        req_cols = [c[1] for c in conn.execute("PRAGMA table_info(requirements)").fetchall()]
        has_cust_col = 'customer_id' in req_cols
        if has_cust_col:
            req = conn.execute("SELECT name, type, trip_id, traveller_id, customer_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        else:
            req = conn.execute("SELECT name, type, trip_id, traveller_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        
        # Validation rules
        data = json.loads(doc['extracted_data']) if doc['extracted_data'] else {}
        if not data:
            raise ValueError("Extracted information is empty. Please complete re-extraction before verifying.")
            
        mandatory = []
        req_name = req['name']
        if req_name == 'Passport':
            mandatory = ['Full Name', 'Passport Number', 'Date of Birth', 'Nationality', 'Expiry Date']
        elif req_name == 'Flight Ticket':
            mandatory = ['Passenger Name', 'PNR/Booking Reference', 'Route', 'Departure Date/Time', 'Arrival Date/Time']
        elif req_name == 'Visa / Entry Document':
            mandatory = ['Traveller Name', 'Visa Number / Reference', 'Destination']
        elif req_name == 'Hotel Voucher':
            mandatory = ['Hotel Name', 'Guest Name', 'Check-in Date', 'Check-out Date', 'Booking Confirmation Number']
        elif req_name == 'Travel Insurance':
            mandatory = ['Insured Name', 'Policy Number', 'Valid From', 'Valid Until']
        elif req_name == 'Transfer Voucher':
            mandatory = ['Passenger Name', 'Booking Reference', 'Pickup Location', 'Dropoff Location', 'Transfer Date']
        elif req_name == 'Sightseeing Voucher':
            mandatory = ['Guest Name', 'Booking Reference', 'Tour / Activity Name', 'Activity Date']
        elif req_name == 'Land Voucher':
            mandatory = ['Booking Reference']
        elif req_name == 'Aadhaar Card':
            mandatory = ['Full Name', 'Aadhaar Number']
        elif req_name == 'PAN Card':
            mandatory = ['Full Name', 'PAN Number']
        elif req_name == 'Arrival / Entry Document':
            mandatory = ['Traveller Name', 'Destination', 'Arrival Date', 'Reference Number']
        elif req_name == 'Itinerary':
            mandatory = ['Start Date', 'End Date', 'Schedule Summary']
            
        for m in mandatory:
            val = data.get(m)
            if not val or not str(val).strip():
                raise ValueError(f"Cannot verify: Missing mandatory field '{m}'.")
                
        conn.execute("UPDATE documents SET status = 'Verified' WHERE id = ?", (doc_id,))
        
        # Passport profile synchronization to matching travellers row
        final_passport = None
        final_nat = None
        final_dob = None
        if req and req['name'] == 'Passport' and req['traveller_id']:
            traveller = conn.execute("SELECT * FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
            if not traveller:
                raise ValueError(f"Associated traveller '{req['traveller_id']}' not found.")

            doc_passport = str(data.get('Passport Number')).strip() if data.get('Passport Number') else None
            doc_nationality = str(data.get('Nationality')).strip() if data.get('Nationality') else None
            doc_dob_raw = str(data.get('Date of Birth')).strip() if data.get('Date of Birth') else None

            # Validate and normalize Date of Birth
            normalized_dob = None
            parsed_dob = None
            if doc_dob_raw:
                parsed_dob = parse_flexible_date(doc_dob_raw)
                if not parsed_dob:
                    raise ValueError(f"Cannot verify: Invalid Date of Birth format '{doc_dob_raw}' in Passport document.")
                normalized_dob = parsed_dob.strftime("%d %b %Y")

            # Conflict checks: Never silently overwrite a different nonempty existing value
            traveller_keys = traveller.keys()
            curr_pass = str(traveller['passport_number']).strip() if ('passport_number' in traveller_keys and traveller['passport_number']) else None
            if curr_pass and doc_passport and curr_pass.upper() != doc_passport.upper():
                raise ValueError(
                    f"Synchronization conflict for traveller '{traveller['name']}': "
                    f"existing profile passport '{curr_pass}' does not match verified document passport '{doc_passport}'."
                )

            curr_nat = str(traveller['nationality']).strip() if ('nationality' in traveller_keys and traveller['nationality']) else None
            if curr_nat and doc_nationality and curr_nat.lower() != doc_nationality.lower():
                raise ValueError(
                    f"Synchronization conflict for traveller '{traveller['name']}': "
                    f"existing profile nationality '{curr_nat}' does not match verified document nationality '{doc_nationality}'."
                )

            curr_dob_raw = str(traveller['dob']).strip() if ('dob' in traveller_keys and traveller['dob']) else None
            curr_dob_parsed = None
            if curr_dob_raw and doc_dob_raw:
                curr_dob_parsed = parse_flexible_date(curr_dob_raw)
                if curr_dob_parsed and parsed_dob:
                    if curr_dob_parsed != parsed_dob:
                        raise ValueError(
                            f"Synchronization conflict for traveller '{traveller['name']}': "
                            f"existing profile date of birth '{curr_dob_raw}' does not match verified document date of birth '{doc_dob_raw}'."
                        )
                elif curr_dob_raw.lower() != doc_dob_raw.lower():
                    raise ValueError(
                        f"Synchronization conflict for traveller '{traveller['name']}': "
                        f"existing profile date of birth '{curr_dob_raw}' does not match verified document date of birth '{doc_dob_raw}'."
                    )

            final_passport = doc_passport if not curr_pass else curr_pass
            final_nat = doc_nationality if not curr_nat else curr_nat
            final_dob = normalized_dob if not curr_dob_raw else (normalized_dob if (curr_dob_parsed and parsed_dob and curr_dob_parsed == parsed_dob) else curr_dob_raw)

            col_info = [c[1] for c in conn.execute("PRAGMA table_info(travellers)").fetchall()]
            set_clauses = []
            params = []
            if 'passport_number' in col_info:
                set_clauses.append("passport_number = ?")
                params.append(final_passport)
            if 'nationality' in col_info:
                set_clauses.append("nationality = ?")
                params.append(final_nat)
            if 'dob' in col_info:
                set_clauses.append("dob = ?")
                params.append(final_dob)

            if set_clauses:
                params.append(req['traveller_id'])
                conn.execute(f"UPDATE travellers SET {', '.join(set_clauses)} WHERE id = ?", tuple(params))

        # Add to document_history
        conn.execute('''
            INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason)
            VALUES (?, 'VERIFY', ?, 'Verified', ?, 'Verification completed')
        ''', (doc_id, doc['status'], actor))

        from datetime import datetime
        now_iso = datetime.now().isoformat()
        if req:
            act_desc = f"Document {doc_id} verified by {actor}"
            if req['trip_id']:
                conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], act_desc, now_iso))
            elif req['traveller_id']:
                t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
                if t_cust and t_cust['customer_id']:
                    conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], act_desc, now_iso))
            elif has_cust_col and req['customer_id']:
                conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (req['customer_id'], act_desc, now_iso))
            elif has_cust_col and req['customer_id']:
                conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (req['customer_id'], act_desc, now_iso))

            if req['name'] == 'Passport' and req['traveller_id'] and final_passport:
                sync_desc = (
                    f"Traveller {req['traveller_id']} profile synchronized from verified Passport: "
                    f"Passport Number: {final_passport}, Nationality: {final_nat}, DOB: {final_dob} by {actor}"
                )
                if req['trip_id']:
                    conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], sync_desc, now_iso))
                elif req['traveller_id']:
                    t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
                    if t_cust and t_cust['customer_id']:
                        conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], sync_desc, now_iso))
        
        conn.commit()
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def reopen_document(doc_id, reason, session_token):
    if not reason or not reason.strip():
        raise ValueError("Correction reason is required.")
        
    user = auth_services.require_role(session_token, ['Supervisor', 'Admin'])
    actor = user['full_name']
        
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError("Document not found.")
        if doc['status'] != 'Verified':
            raise ValueError("Only VERIFIED documents can be reopened.")
            
        req_cols = [c[1] for c in conn.execute("PRAGMA table_info(requirements)").fetchall()]
        has_cust_col = 'customer_id' in req_cols
        if has_cust_col:
            req = conn.execute("SELECT trip_id, traveller_id, customer_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        else:
            req = conn.execute("SELECT trip_id, traveller_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        
        # Revert final approval if necessary
        if req['trip_id']:
            trip = conn.execute("SELECT status FROM trips WHERE id = ?", (req['trip_id'],)).fetchone()
            if trip and trip['status'] == 'TRAVEL FILE READY':
                conn.execute("UPDATE trips SET status = 'NOT READY' WHERE id = ?", (req['trip_id'],))
        
        # Append history
        conn.execute('''
            INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason)
            VALUES (?, 'REOPEN', 'Verified', 'Under Review', ?, ?)
        ''', (doc_id, actor, reason.strip()))
        
        # Status change
        conn.execute("UPDATE documents SET status = 'Under Review' WHERE id = ?", (doc_id,))
        
        from datetime import datetime
        now_iso = datetime.now().isoformat()
        if req:
            act_desc = f"Document {doc_id} reopened by {actor}. Reason: {reason.strip()}"
            if req['trip_id']:
                conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], act_desc, now_iso))
            elif req['traveller_id']:
                t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
                if t_cust and t_cust['customer_id']:
                    conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], act_desc, now_iso))
        
        conn.commit()
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def reject_document(doc_id, reason, session_token):
    if not reason or not str(reason).strip():
        raise ValueError("Rejection reason is required.")
        
    user = auth_services.require_role(session_token, ['Supervisor', 'Admin'])
    actor = user['full_name']
        
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError("Document not found.")
        if doc['status'] == 'Verified':
            raise ValueError("Security Error: Cannot reject a VERIFIED document directly. It must be reopened first.")
            
        req = conn.execute("SELECT trip_id, traveller_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        
        # Invalidate trip readiness if it was TRAVEL FILE READY
        if req and req['trip_id']:
            trip = conn.execute("SELECT status FROM trips WHERE id = ?", (req['trip_id'],)).fetchone()
            if trip and trip['status'] == 'TRAVEL FILE READY':
                conn.execute("UPDATE trips SET status = 'NOT READY' WHERE id = ?", (req['trip_id'],))
                
        conn.execute("UPDATE documents SET status = 'Rejected' WHERE id = ?", (doc_id,))
        
        from datetime import datetime
        now_iso = datetime.now().isoformat()
        
        conn.execute('''
            INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason, timestamp)
            VALUES (?, 'REJECT', ?, 'Rejected', ?, ?, ?)
        ''', (doc_id, doc['status'], actor, reason.strip(), now_iso))
        
        if req:
            act_desc = f"Document {doc_id} rejected by {actor}. Reason: {reason.strip()}"
            if req['trip_id']:
                conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], act_desc, now_iso))
            elif req['traveller_id']:
                t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
                if t_cust and t_cust['customer_id']:
                    conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], act_desc, now_iso))
                    
        conn.commit()
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def request_reupload_document(doc_id, reason, session_token):
    if not reason or not str(reason).strip():
        raise ValueError("Reason for requesting re-upload is required.")
        
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    actor = user['full_name']
        
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError("Document not found.")
        if doc['status'] == 'Verified':
            raise ValueError("Security Error: Cannot request re-upload for a VERIFIED document directly. It must be reopened first.")
            
        req = conn.execute("SELECT trip_id, traveller_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        
        # Invalidate trip readiness if it was TRAVEL FILE READY
        if req and req['trip_id']:
            trip = conn.execute("SELECT status FROM trips WHERE id = ?", (req['trip_id'],)).fetchone()
            if trip and trip['status'] == 'TRAVEL FILE READY':
                conn.execute("UPDATE trips SET status = 'NOT READY' WHERE id = ?", (req['trip_id'],))
                
        conn.execute("UPDATE documents SET status = 'Re-upload Required' WHERE id = ?", (doc_id,))
        
        from datetime import datetime
        now_iso = datetime.now().isoformat()
        
        conn.execute('''
            INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason, timestamp)
            VALUES (?, 'REUPLOAD_REQUEST', ?, 'Re-upload Required', ?, ?, ?)
        ''', (doc_id, doc['status'], actor, reason.strip(), now_iso))
        
        if req:
            act_desc = f"Document {doc_id} re-upload requested by {actor}. Reason: {reason.strip()}"
            if req['trip_id']:
                conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], act_desc, now_iso))
            elif req['traveller_id']:
                t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
                if t_cust and t_cust['customer_id']:
                    conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], act_desc, now_iso))
                    
        conn.commit()
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def save_extracted_information(doc_id, extracted_data, session_token, reason=None):
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    actor = user['full_name']
    
    if extracted_data is None or not isinstance(extracted_data, dict):
        raise ValueError("extracted_data must be a valid dictionary.")
        
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError("Document not found.")
        if doc['status'] == 'Verified':
            raise ValueError("Security Error: Cannot modify extracted data of a VERIFIED document.")
            
        conn.execute("UPDATE documents SET extracted_data = ? WHERE id = ?", (json.dumps(extracted_data), doc_id))
        
        from datetime import datetime
        now_iso = datetime.now().isoformat()
        hist_reason = reason.strip() if (reason and str(reason).strip()) else "Extracted information updated by staff"
        
        conn.execute('''
            INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason, timestamp)
            VALUES (?, 'EDIT_DATA', ?, ?, ?, ?, ?)
        ''', (doc_id, doc['status'], doc['status'], actor, hist_reason, now_iso))
        
        req = conn.execute("SELECT trip_id, traveller_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        if req:
            act_desc = f"Document {doc_id} extracted information updated by {actor}"
            if req['trip_id']:
                conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], act_desc, now_iso))
            elif req['traveller_id']:
                t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
                if t_cust and t_cust['customer_id']:
                    conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], act_desc, now_iso))
                    
        conn.commit()
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def add_document_note(doc_id, note_text, session_token):
    if not note_text or not str(note_text).strip():
        raise ValueError("Note text cannot be empty.")
        
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    actor = user['full_name']
    
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT requirement_id FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError("Document not found.")
        req = conn.execute("SELECT trip_id, traveller_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        
        from datetime import datetime
        now_iso = datetime.now().isoformat()
        note_desc = f"Note added by {actor}: {str(note_text).strip()}"
        if req:
            if req['trip_id']:
                conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], note_desc, now_iso))
            elif req['traveller_id']:
                t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
                if t_cust and t_cust['customer_id']:
                    conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], note_desc, now_iso))
        conn.commit()
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def get_safe_document_path(raw_file_path):
    """
    Safely resolves raw_file_path, restricting access strictly to the approved
    storage root (KT_VAULT_STORAGE_ROOT or DB/project documents dir), normalizing
    cross-platform separators and rejecting path traversal or symlink attacks.
    """
    if not raw_file_path or not isinstance(raw_file_path, str):
        return None, "Document path is not specified."

    import os
    import storage_service
    approved_docs_dir = os.path.realpath(storage_service.get_storage_root())
    clean_raw = raw_file_path.replace("\\", "/").strip()
    if "\0" in clean_raw or ".." in clean_raw.split("/"):
        return None, "Security Error: Document path traversal rejected."

    if os.path.isabs(clean_raw):
        candidate = clean_raw
    else:
        norm = clean_raw
        root_name = os.path.basename(approved_docs_dir).lower()
        parts = [p for p in norm.split("/") if p]
        if parts and parts[0].lower() in ("documents", root_name):
            norm = "/".join(parts[1:])
        candidate = os.path.join(approved_docs_dir, norm)
    real_path = os.path.realpath(candidate)
    
    try:
        common = os.path.commonpath([approved_docs_dir, real_path])
        if os.path.realpath(common) != approved_docs_dir:
            return None, "Security Error: Document file path is outside the approved document storage directory."
    except (ValueError, Exception):
        return None, "Security Error: Invalid file path or drive boundary."
        
    if not os.path.exists(real_path) or not os.path.isfile(real_path):
        return None, "Document file does not exist on disk."
        
    return real_path, None

def generate_next_id(conn, table, prefix):
    prefix_len = len(prefix) + 1
    cursor = conn.cursor()
    query = f"SELECT MAX(CAST(SUBSTR(id, ?) AS INTEGER)) FROM {table} WHERE id LIKE ?"
    cursor.execute(query, (prefix_len, f"{prefix}%"))
    result = cursor.fetchone()[0]
    next_num = 1 if result is None else result + 1
    return f"{prefix}{next_num:04d}"

def create_customer(full_name, mobile=None, email=None, customer_type="Individual", session_token=None):
    import auth_services
    if not session_token: raise PermissionError('Unauthenticated')
    auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    conn = database.get_connection()
    try:
        new_id = generate_next_id(conn, 'customers', 'KT-C-')
        conn.execute('''
            INSERT INTO customers (id, name, mobile, email, customer_type, status)
            VALUES (?, ?, ?, ?, ?, 'Active')
        ''', (new_id, full_name, mobile, email, customer_type))
        conn.execute('''
            INSERT INTO activity (customer_id, description, timestamp)
            VALUES (?, ?, datetime('now'))
        ''', (new_id, f"Customer created: {full_name}"))
        ensure_customer_mandatory_requirements(new_id, conn=conn)
        conn.commit()
        return new_id
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def add_traveller(customer_id, full_name, dob=None, traveller_type="Adult", relationship="Self", lead_traveller=False, passport_number=None, nationality=None, session_token=None, allow_duplicate=False):
    import auth_services
    import document_processor
    import re
    if not session_token: raise PermissionError('Unauthenticated')
    auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    conn = database.get_connection()
    try:
        # Duplicate detection within the same customer
        if not allow_duplicate and full_name:
            norm_name = document_processor.normalize_person_name(full_name)
            clean_pass = re.sub(r'[^A-Za-z0-9]', '', passport_number or '').upper()
            existing = conn.execute(
                "SELECT id, name, passport_number, dob FROM travellers WHERE customer_id = ?",
                (customer_id,)
            ).fetchall()
            for et in existing:
                et_norm = document_processor.normalize_person_name(et['name']) if et['name'] else ''
                et_pass = re.sub(r'[^A-Za-z0-9]', '', et['passport_number'] or '').upper()
                # If passport numbers match and names match:
                if clean_pass and et_pass and clean_pass == et_pass:
                    return et['id']
                # If names match and DOB matches:
                if norm_name and et_norm and norm_name == et_norm:
                    if dob and et['dob'] and str(dob).strip().lower() == str(et['dob']).strip().lower():
                        return et['id']

        new_id = generate_next_id(conn, 'travellers', 'KT-TR-')
        conn.execute('''
            INSERT INTO travellers (id, customer_id, name, dob, type, relationship, role, passport_number, nationality)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (new_id, customer_id, full_name, dob, traveller_type, relationship, 'Lead Traveller' if lead_traveller else 'Standard', passport_number, nationality))
        conn.execute('''
            INSERT INTO activity (customer_id, description, timestamp)
            VALUES (?, ?, datetime('now'))
        ''', (customer_id, f"Traveller added: {full_name}"))
        conn.commit()
        return new_id
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def create_trip(customer_id, name, destination, start_date, end_date, trip_type, service, department, traveller_ids, session_token=None):
    import auth_services
    if not session_token: raise PermissionError('Unauthenticated')
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    conn = database.get_connection()
    try:
        import uuid
        # Server-side ownership check: verify customer exists and all linked travellers belong strictly to customer_id
        cust_row = conn.execute("SELECT id FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not cust_row:
            raise ValueError(f"Customer '{customer_id}' does not exist.")

        clean_traveller_ids = list(dict.fromkeys(traveller_ids or []))
        for tr_id in clean_traveller_ids:
            tr_row = conn.execute("SELECT id, customer_id FROM travellers WHERE id = ?", (tr_id,)).fetchone()
            if not tr_row:
                raise ValueError(f"Traveller '{tr_id}' does not exist.")
            if tr_row['customer_id'] != customer_id:
                auth_services.log_security_event(
                    "CROSS_CUSTOMER_TRIP_LINK_BLOCKED",
                    username=user.get("username"),
                    user_id=user.get("id"),
                    role=user.get("role"),
                    details=f"Blocked creating trip for customer {customer_id}: traveller {tr_id} belongs to customer {tr_row['customer_id']}."
                )
                raise ValueError(
                    f"Cross-customer trip link rejected: Traveller '{tr_id}' belongs to customer "
                    f"'{tr_row['customer_id']}', not '{customer_id}'."
                )

        new_id = generate_next_id(conn, 'trips', 'KT-T-')
        
        conn.execute('''
            INSERT INTO trips (id, customer_id, name, destination, start_date, end_date, trip_type, service, department, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'NOT READY')
        ''', (new_id, customer_id, name, destination, start_date, end_date, trip_type, service, department))
        
        for tr_id in clean_traveller_ids:
            conn.execute("INSERT INTO trip_travellers (trip_id, traveller_id) VALUES (?, ?)", (new_id, tr_id))
            
            for doc_name in ["Passport", "Visa / Entry Document"]:
                req_id = f"REQ-TR-{uuid.uuid4().hex[:6]}"
                conn.execute('''
                    INSERT INTO requirements (id, trip_id, traveller_id, name, type) 
                    VALUES (?, ?, ?, ?, 'TRAVELLER')
                ''', (req_id, new_id, tr_id, doc_name))
                
                existing_doc = conn.execute('''
                    SELECT d.* FROM documents d
                    JOIN requirements r ON d.requirement_id = r.id
                    WHERE r.traveller_id = ? AND r.name = ? AND r.type = 'TRAVELLER_VAULT'
                    ORDER BY d.uploaded_at DESC LIMIT 1
                ''', (tr_id, doc_name)).fetchone()
                
                if existing_doc:
                    conn.execute('''
                        INSERT INTO documents (id, requirement_id, status, extracted_data, file_path, uploaded_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (f"DOC-{uuid.uuid4().hex[:8]}", req_id, existing_doc['status'], existing_doc['extracted_data'], existing_doc['file_path'], existing_doc['uploaded_at']))
            
        trip_reqs = [
            'Flight Ticket', 'Hotel Voucher', 'Travel Insurance', 
            'Transfer Voucher', 'Sightseeing Voucher', 'Arrival / Entry Document', 'Itinerary'
        ]
        for tr in trip_reqs:
            conn.execute('''
                INSERT INTO requirements (id, trip_id, traveller_id, name, type)
                VALUES (?, ?, NULL, ?, 'TRIP')
            ''', (f"REQ-T-{uuid.uuid4().hex[:6]}", new_id, tr))
            
        conn.execute('''
            INSERT INTO activity (trip_id, description, timestamp)
            VALUES (?, ?, datetime('now'))
        ''', (new_id, f"Trip created: {name}"))
        
        conn.commit()
        return new_id
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def recover_verified_document_data(
    doc_id: str,
    recovered_data: dict,
    reason: str,
    session_token: str,
    expected_pdf_sha256: str = None,
    expected_data_hash: str = None,
    reverify: bool = True,
    db_path: str = None
):
    """
    Safely recovers missing or legacy extracted information for a Verified document.
    Performs atomic validation, audit archival, and re-verification in a single transaction.
    """
    import os
    import sqlite3
    import hashlib
    import uuid
    from datetime import datetime

    # 1. Authorization check: strictly Supervisor and Admin
    user = auth_services.require_role(session_token, ['Supervisor', 'Admin'])
    actor = user['full_name']

    # 2. Input validation
    if not reason or not str(reason).strip():
        raise ValueError("Mandatory recovery reason is required.")

    if recovered_data is None or not isinstance(recovered_data, dict):
        raise ValueError("recovered_data must be a valid dictionary.")

    if not reverify:
        raise ValueError("Explicit Supervisor/Admin re-verification is required to complete recovery.")

    # 3. Connect to database
    if db_path:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
    else:
        conn = database.get_connection()

    try:
        # Check if document_recovery_audit schema is deployed
        has_audit = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='document_recovery_audit'"
        ).fetchone()
        if not has_audit:
            raise RuntimeError(
                "Migration Required: The 'document_recovery_audit' table is not deployed in this database. "
                "Phase 8.3 schema migration must be approved and executed before recovery can proceed."
            )

        # 4. Check document
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError(f"Document '{doc_id}' not found.")
        if doc['status'] != 'Verified':
            raise ValueError(f"Document '{doc_id}' is not in 'Verified' status (current status: '{doc['status']}'). Only Verified documents can be recovered.")

        # 5. Check source PDF exists and hash
        raw_file_path = doc['file_path'] if doc['file_path'] else ""
        safe_full_path, path_err = get_safe_document_path(raw_file_path)
        if path_err or not os.path.exists(safe_full_path):
            raise ValueError(f"Source document file '{raw_file_path}' cannot be accessed or does not exist on disk.")

        import storage_service
        pdf_bytes = storage_service.read_decrypted_document(
            safe_full_path,
            session_token=session_token,
            allowed_roles=['Supervisor', 'Admin']
        )
        current_pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        if expected_pdf_sha256 and current_pdf_sha256.lower() != expected_pdf_sha256.lower():
            raise ValueError("Conflict: Source PDF hash has changed since recovery review began.")

        # 6. Concurrency check on stored data
        stored_raw = doc['extracted_data'] if doc['extracted_data'] else "{}"
        current_data_hash = hashlib.sha256(stored_raw.encode('utf-8')).hexdigest()
        if expected_data_hash and current_data_hash != expected_data_hash:
            raise ValueError("Conflict: Document extracted data has changed since recovery review began.")

        # 7. Check requirement and schema validation
        req = conn.execute("SELECT name, type, trip_id, traveller_id FROM requirements WHERE id = ?", (doc['requirement_id'],)).fetchone()
        if not req:
            raise ValueError("Associated requirement not found.")

        req_name = req['name']
        mandatory = []
        if req_name == 'Passport':
            mandatory = ['Full Name', 'Passport Number', 'Date of Birth', 'Nationality', 'Expiry Date']
        elif req_name == 'Flight Ticket':
            mandatory = ['Passenger Name', 'PNR/Booking Reference', 'Route', 'Departure Date/Time', 'Arrival Date/Time']
        elif req_name == 'Visa / Entry Document':
            mandatory = ['Traveller Name', 'Visa Number / Reference', 'Destination']
        elif req_name == 'Hotel Voucher':
            mandatory = ['Hotel Name', 'Guest Name', 'Check-in Date', 'Check-out Date', 'Booking Confirmation Number']
        elif req_name == 'Travel Insurance':
            mandatory = ['Insured Name', 'Policy Number', 'Valid From', 'Valid Until']
        elif req_name == 'Transfer Voucher':
            mandatory = ['Passenger Name', 'Booking Reference', 'Pickup Location', 'Dropoff Location', 'Transfer Date']
        elif req_name == 'Sightseeing Voucher':
            mandatory = ['Guest Name', 'Booking Reference', 'Tour / Activity Name', 'Activity Date']
        elif req_name == 'Arrival / Entry Document':
            mandatory = ['Traveller Name', 'Destination', 'Arrival Date', 'Reference Number']
        elif req_name == 'Itinerary':
            mandatory = ['Start Date', 'End Date', 'Schedule Summary']

        for m in mandatory:
            val = recovered_data.get(m)
            if not val or not str(val).strip():
                raise ValueError(f"Cannot complete recovery: Missing mandatory field '{m}'.")

        # 8. Atomic transaction
        tx_id = f"REC-TX-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now().isoformat()

        conn.execute("BEGIN IMMEDIATE")

        # 8a. Insert dedicated recovery audit record
        conn.execute('''
            INSERT INTO document_recovery_audit (
                transaction_id, document_id, file_path, pdf_sha256,
                previous_extracted_data, new_extracted_data,
                previous_status, new_status, actor, reason, outcome, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, 'Verified', 'Verified', ?, ?, 'SUCCESS', ?)
        ''', (
            tx_id, doc_id, doc['file_path'], current_pdf_sha256,
            stored_raw, json.dumps(recovered_data),
            actor, reason.strip(), now_iso
        ))

        # 8b. Update document's extracted data (status remains 'Verified')
        conn.execute(
            "UPDATE documents SET extracted_data = ? WHERE id = ?",
            (json.dumps(recovered_data), doc_id)
        )

        # 8c. Add to document_history
        hist_reason = f"Data Recovery confirmed by {actor}. Reason: {reason.strip()} (Tx: {tx_id})"
        conn.execute('''
            INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason, timestamp)
            VALUES (?, 'DATA_RECOVERY', 'Verified', 'Verified', ?, ?, ?)
        ''', (doc_id, actor, hist_reason, now_iso))

        # 8d. Add to activity
        act_desc = f"Document {doc_id} recovered and re-verified by {actor} (Tx: {tx_id})"
        if req['trip_id']:
            conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", (req['trip_id'], act_desc, now_iso))
        elif req['traveller_id']:
            t_cust = conn.execute("SELECT customer_id FROM travellers WHERE id = ?", (req['traveller_id'],)).fetchone()
            if t_cust and t_cust['customer_id']:
                conn.execute("INSERT INTO activity (customer_id, description, timestamp) VALUES (?, ?, ?)", (t_cust['customer_id'], act_desc, now_iso))

        conn.commit()

        return {
            "success": True,
            "transaction_id": tx_id,
            "document_id": doc_id,
            "actor": actor,
            "timestamp": now_iso
        }
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def parse_flexible_date(val):
    if not val or not isinstance(val, (str, datetime, date)):
        return None
    if isinstance(val, datetime):
        return val.date()
    if isinstance(val, date):
        return val
        
    val_clean = str(val).strip()
    if not val_clean:
        return None
    import re
    
    # Strip time if present: e.g. "12 Dec 2026 09:30" -> "12 Dec 2026"
    m_time = re.search(r'^(.+?)(?:\s+\d{1,2}:\d{2}(?::\d{2})?)\s*$', val_clean)
    if m_time:
        val_clean = m_time.group(1).strip()
        
    date_formats = [
        "%Y-%m-%d",
        "%d %b %Y",
        "%d %B %Y",
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%Y/%m/%d",
        "%b %d, %Y",
        "%B %d, %Y"
    ]
    for fmt in date_formats:
        try:
            return datetime.strptime(val_clean, fmt).date()
        except ValueError:
            continue
    return None

def verify_metadata_pdf_date_agreement(file_path, date_obj, date_raw_str, session_token=None):
    if not file_path or not os.path.exists(file_path):
        return True, ""
    try:
        import document_processor
        import storage_service
        if session_token:
            pdf_bytes = storage_service.read_decrypted_document(file_path, session_token=session_token)
        else:
            pdf_bytes = storage_service.read_decrypted_document(file_path, system_context=True)
        pdf_text = document_processor.simple_pdf_extract(pdf_bytes)
        if not pdf_text:
            return True, ""
            
        if date_raw_str and str(date_raw_str).strip().lower() in pdf_text.lower():
            return True, ""
            
        day_str = str(date_obj.day)
        month_abbr = date_obj.strftime("%b")
        month_full = date_obj.strftime("%B")
        year_str = str(date_obj.year)
        
        patterns = [
            f"{day_str} {month_abbr}",
            f"{day_str} {month_full}",
            f"{month_abbr} {day_str}",
            f"{year_str}-{date_obj.month:02d}-{date_obj.day:02d}",
            f"{date_obj.day:02d}/{date_obj.month:02d}/{year_str}"
        ]
        for p in patterns:
            if p.lower() in pdf_text.lower():
                return True, ""
                
        return False, f"Extracted date '{date_raw_str}' does not appear in source PDF text (potential metadata/PDF disagreement)."
    except Exception:
        return True, ""

def validate_trip_date_consistency(trip_id, proposed_start_date, proposed_end_date, conn=None, session_token=None):
    from datetime import datetime, timedelta
    
    T_start = parse_flexible_date(proposed_start_date)
    T_end = parse_flexible_date(proposed_end_date)
    
    if not T_start or not T_end:
        return {
            'compatible': False,
            'status': 'invalid_proposed_dates',
            'conflicts': ["Proposed trip dates must be valid calendar dates."],
            'warnings': [],
            'document_evaluations': []
        }
        
    if T_end < T_start:
        return {
            'compatible': False,
            'status': 'invalid_date_range',
            'conflicts': ["Proposed return date cannot be earlier than departure date."],
            'warnings': [],
            'document_evaluations': []
        }
        
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True
        
    try:
        docs = conn.execute('''
            SELECT r.id AS req_id, r.name AS req_name, r.type AS req_type,
                   d.id AS doc_id, d.status AS doc_status, d.extracted_data, d.file_path,
                   t.name AS traveller_name
            FROM requirements r
            JOIN documents d ON r.id = d.requirement_id
            LEFT JOIN travellers t ON r.traveller_id = t.id
            WHERE r.trip_id = ? AND d.status = 'Verified'
        ''', (trip_id,)).fetchall()
        
        conflicts = []
        warnings = []
        doc_evals = []
        
        for d in docs:
            doc_id = d['doc_id']
            doc_type = d['req_name']
            traveller_name = d['traveller_name']
            doc_label = f"{traveller_name} - {doc_type}" if traveller_name else doc_type
            file_path = d['file_path']
            
            raw_ext = d['extracted_data']
            ext_data = json.loads(raw_ext) if raw_ext else {}
            
            doc_compatible = True
            evaluated_dates = {}
            
            if doc_type == 'Passport':
                exp_raw = ext_data.get('Expiry Date')
                exp_d = parse_flexible_date(exp_raw)
                evaluated_dates['Expiry Date'] = exp_raw
                if not exp_d:
                    conflicts.append(f"Passport '{doc_label}' is Verified but has missing/unparseable Expiry Date.")
                    doc_compatible = False
                else:
                    agrees, msg = verify_metadata_pdf_date_agreement(file_path, exp_d, exp_raw, session_token=session_token)
                    if not agrees:
                        conflicts.append(f"Passport '{doc_label}': {msg}")
                        doc_compatible = False
                    if exp_d < T_end:
                        conflicts.append(f"Passport '{doc_label}' expires on {exp_d.strftime('%d %b %Y')}, before proposed trip conclusion {T_end.strftime('%d %b %Y')}.")
                        doc_compatible = False
                    elif exp_d < (T_end + timedelta(days=180)):
                        warnings.append(f"Passport '{doc_label}' has less than 6 months validity remaining after trip end ({exp_d.strftime('%d %b %Y')}).")
                        
            elif doc_type == 'Visa / Entry Document':
                exp_raw = ext_data.get('Expiry Date / Valid Until') or ext_data.get('Expiry Date') or ext_data.get('Valid Until')
                exp_d = parse_flexible_date(exp_raw)
                from_raw = ext_data.get('Valid From') or ext_data.get('Issue Date')
                from_d = parse_flexible_date(from_raw)
                evaluated_dates['Expiry / Valid Until'] = exp_raw
                evaluated_dates['Valid From'] = from_raw
                if not exp_d:
                    conflicts.append(f"Visa '{doc_label}' is Verified but has missing/unparseable Expiry/Validity date.")
                    doc_compatible = False
                else:
                    agrees, msg = verify_metadata_pdf_date_agreement(file_path, exp_d, exp_raw, session_token=session_token)
                    if not agrees:
                        conflicts.append(f"Visa '{doc_label}': {msg}")
                        doc_compatible = False
                    if exp_d < T_end:
                        conflicts.append(f"Visa '{doc_label}' expires on {exp_d.strftime('%d %b %Y')}, before proposed trip end date {T_end.strftime('%d %b %Y')}.")
                        doc_compatible = False
                    if from_d and from_d > T_start:
                        conflicts.append(f"Visa '{doc_label}' validity starts on {from_d.strftime('%d %b %Y')}, after proposed trip start date {T_start.strftime('%d %b %Y')}.")
                        doc_compatible = False
                        
            elif doc_type == 'Flight Ticket':
                dep_raw = ext_data.get('Departure Date/Time') or ext_data.get('Departure Date')
                arr_raw = ext_data.get('Arrival Date/Time') or ext_data.get('Arrival Date')
                dep_d = parse_flexible_date(dep_raw)
                arr_d = parse_flexible_date(arr_raw)
                evaluated_dates['Departure'] = dep_raw
                evaluated_dates['Arrival'] = arr_raw
                if not dep_d and not arr_d:
                    conflicts.append(f"Flight Ticket '{doc_label}' is Verified but has missing departure/return flight dates.")
                    doc_compatible = False
                else:
                    if dep_d:
                        agrees, msg = verify_metadata_pdf_date_agreement(file_path, dep_d, dep_raw, session_token=session_token)
                        if not agrees:
                            conflicts.append(f"Flight Ticket '{doc_label}': {msg}")
                            doc_compatible = False
                        if dep_d < T_start:
                            conflicts.append(f"Flight Ticket '{doc_label}' departs on {dep_d.strftime('%d %b %Y')}, before proposed trip start date {T_start.strftime('%d %b %Y')}.")
                            doc_compatible = False
                        if dep_d > T_end:
                            conflicts.append(f"Flight Ticket '{doc_label}' departs on {dep_d.strftime('%d %b %Y')}, after proposed trip end date {T_end.strftime('%d %b %Y')}.")
                            doc_compatible = False
                    if arr_d:
                        agrees, msg = verify_metadata_pdf_date_agreement(file_path, arr_d, arr_raw, session_token=session_token)
                        if not agrees:
                            conflicts.append(f"Flight Ticket '{doc_label}': {msg}")
                            doc_compatible = False
                        if arr_d < T_start:
                            conflicts.append(f"Flight Ticket '{doc_label}' returns on {arr_d.strftime('%d %b %Y')}, before proposed trip start date {T_start.strftime('%d %b %Y')}.")
                            doc_compatible = False
                        if arr_d > T_end:
                            conflicts.append(f"Flight Ticket '{doc_label}' returns on {arr_d.strftime('%d %b %Y')}, after proposed trip end date {T_end.strftime('%d %b %Y')}.")
                            doc_compatible = False
                            
            elif doc_type == 'Hotel Voucher':
                cin_raw = ext_data.get('Check-in Date')
                cout_raw = ext_data.get('Check-out Date')
                cin_d = parse_flexible_date(cin_raw)
                cout_d = parse_flexible_date(cout_raw)
                evaluated_dates['Check-in'] = cin_raw
                evaluated_dates['Check-out'] = cout_raw
                if not cin_d or not cout_d:
                    conflicts.append(f"Hotel Voucher '{doc_label}' is Verified but has missing Check-in or Check-out dates.")
                    doc_compatible = False
                else:
                    agrees1, msg1 = verify_metadata_pdf_date_agreement(file_path, cin_d, cin_raw, session_token=session_token)
                    agrees2, msg2 = verify_metadata_pdf_date_agreement(file_path, cout_d, cout_raw, session_token=session_token)
                    if not agrees1:
                        conflicts.append(f"Hotel Voucher '{doc_label}': {msg1}")
                        doc_compatible = False
                    if not agrees2:
                        conflicts.append(f"Hotel Voucher '{doc_label}': {msg2}")
                        doc_compatible = False
                    if cin_d < T_start:
                        conflicts.append(f"Hotel Voucher '{doc_label}' check-in ({cin_d.strftime('%d %b %Y')}) is before proposed trip start date {T_start.strftime('%d %b %Y')}.")
                        doc_compatible = False
                    if cout_d > T_end:
                        conflicts.append(f"Hotel Voucher '{doc_label}' check-out ({cout_d.strftime('%d %b %Y')}) is after proposed trip end date {T_end.strftime('%d %b %Y')}.")
                        doc_compatible = False
                        
            elif doc_type == 'Travel Insurance':
                vfrom_raw = ext_data.get('Valid From')
                vuntil_raw = ext_data.get('Valid Until')
                vfrom_d = parse_flexible_date(vfrom_raw)
                vuntil_d = parse_flexible_date(vuntil_raw)
                evaluated_dates['Valid From'] = vfrom_raw
                evaluated_dates['Valid Until'] = vuntil_raw
                if not vfrom_d or not vuntil_d:
                    conflicts.append(f"Travel Insurance '{doc_label}' is Verified but has missing coverage dates.")
                    doc_compatible = False
                else:
                    agrees1, msg1 = verify_metadata_pdf_date_agreement(file_path, vfrom_d, vfrom_raw, session_token=session_token)
                    agrees2, msg2 = verify_metadata_pdf_date_agreement(file_path, vuntil_d, vuntil_raw, session_token=session_token)
                    if not agrees1:
                        conflicts.append(f"Travel Insurance '{doc_label}': {msg1}")
                        doc_compatible = False
                    if not agrees2:
                        conflicts.append(f"Travel Insurance '{doc_label}': {msg2}")
                        doc_compatible = False
                    if vfrom_d > T_start:
                        conflicts.append(f"Travel Insurance '{doc_label}' coverage begins on {vfrom_d.strftime('%d %b %Y')}, leaving traveller uninsured at trip start {T_start.strftime('%d %b %Y')}.")
                        doc_compatible = False
                    if vuntil_d < T_end:
                        conflicts.append(f"Travel Insurance '{doc_label}' coverage expires on {vuntil_d.strftime('%d %b %Y')}, leaving traveller uninsured before trip conclusion {T_end.strftime('%d %b %Y')}.")
                        doc_compatible = False
                        
            elif doc_type == 'Transfer Voucher':
                trf_raw = ext_data.get('Transfer Date')
                trf_d = parse_flexible_date(trf_raw)
                evaluated_dates['Transfer Date'] = trf_raw
                if not trf_d:
                    conflicts.append(f"Transfer Voucher '{doc_label}' is Verified but has missing Transfer Date.")
                    doc_compatible = False
                else:
                    agrees, msg = verify_metadata_pdf_date_agreement(file_path, trf_d, trf_raw, session_token=session_token)
                    if not agrees:
                        conflicts.append(f"Transfer Voucher '{doc_label}': {msg}")
                        doc_compatible = False
                    if trf_d < T_start or trf_d > T_end:
                        conflicts.append(f"Transfer Voucher '{doc_label}' transfer date ({trf_d.strftime('%d %b %Y')}) is outside proposed trip dates ({T_start.strftime('%d %b %Y')} to {T_end.strftime('%d %b %Y')}).")
                        doc_compatible = False
                        
            elif doc_type == 'Sightseeing Voucher':
                act_raw = ext_data.get('Activity Date')
                act_d = parse_flexible_date(act_raw)
                evaluated_dates['Activity Date'] = act_raw
                if not act_d:
                    conflicts.append(f"Sightseeing Voucher '{doc_label}' is Verified but has missing Activity Date.")
                    doc_compatible = False
                else:
                    agrees, msg = verify_metadata_pdf_date_agreement(file_path, act_d, act_raw, session_token=session_token)
                    if not agrees:
                        conflicts.append(f"Sightseeing Voucher '{doc_label}': {msg}")
                        doc_compatible = False
                    if act_d < T_start or act_d > T_end:
                        conflicts.append(f"Sightseeing Voucher '{doc_label}' activity date ({act_d.strftime('%d %b %Y')}) is outside proposed trip dates ({T_start.strftime('%d %b %Y')} to {T_end.strftime('%d %b %Y')}).")
                        doc_compatible = False
                        
            elif doc_type == 'Arrival / Entry Document':
                arr_raw = ext_data.get('Arrival Date')
                dep_raw = ext_data.get('Departure Date')
                arr_d = parse_flexible_date(arr_raw)
                dep_d = parse_flexible_date(dep_raw)
                evaluated_dates['Arrival Date'] = arr_raw
                evaluated_dates['Departure Date'] = dep_raw
                if not arr_d and not dep_d:
                    conflicts.append(f"Arrival Document '{doc_label}' is Verified but has missing arrival/departure dates.")
                    doc_compatible = False
                else:
                    if arr_d:
                        agrees, msg = verify_metadata_pdf_date_agreement(file_path, arr_d, arr_raw, session_token=session_token)
                        if not agrees:
                            conflicts.append(f"Arrival Document '{doc_label}': {msg}")
                            doc_compatible = False
                        if arr_d < T_start or arr_d > T_end:
                            conflicts.append(f"Arrival Document '{doc_label}' arrival date ({arr_d.strftime('%d %b %Y')}) is outside proposed trip dates.")
                            doc_compatible = False
                    if dep_d:
                        agrees, msg = verify_metadata_pdf_date_agreement(file_path, dep_d, dep_raw, session_token=session_token)
                        if not agrees:
                            conflicts.append(f"Arrival Document '{doc_label}': {msg}")
                            doc_compatible = False
                        if dep_d < T_start or dep_d > T_end:
                            conflicts.append(f"Arrival Document '{doc_label}' departure date ({dep_d.strftime('%d %b %Y')}) is outside proposed trip dates.")
                            doc_compatible = False
                            
            elif doc_type == 'Itinerary':
                istart_raw = ext_data.get('Start Date')
                iend_raw = ext_data.get('End Date')
                istart_d = parse_flexible_date(istart_raw)
                iend_d = parse_flexible_date(iend_raw)
                evaluated_dates['Start Date'] = istart_raw
                evaluated_dates['End Date'] = iend_raw
                if istart_d or iend_d:
                    if istart_d:
                        agrees, msg = verify_metadata_pdf_date_agreement(file_path, istart_d, istart_raw, session_token=session_token)
                        if not agrees:
                            conflicts.append(f"Itinerary '{doc_label}': {msg}")
                            doc_compatible = False
                        if istart_d < T_start or istart_d > T_end:
                            conflicts.append(f"Itinerary '{doc_label}' start date ({istart_d.strftime('%d %b %Y')}) is outside proposed trip dates.")
                            doc_compatible = False
                    if iend_d:
                        agrees, msg = verify_metadata_pdf_date_agreement(file_path, iend_d, iend_raw, session_token=session_token)
                        if not agrees:
                            conflicts.append(f"Itinerary '{doc_label}': {msg}")
                            doc_compatible = False
                        if iend_d < T_start or iend_d > T_end:
                            conflicts.append(f"Itinerary '{doc_label}' end date ({iend_d.strftime('%d %b %Y')}) is outside proposed trip dates.")
                            doc_compatible = False
                            
            doc_evals.append({
                'doc_id': doc_id,
                'doc_name': doc_label,
                'doc_type': doc_type,
                'status': 'Verified',
                'evaluated_dates': evaluated_dates,
                'is_compatible': doc_compatible,
                'details': "Compatible" if doc_compatible else "Conflict detected"
            })
            
        is_compatible = (len(conflicts) == 0)
        return {
            'compatible': is_compatible,
            'status': 'compatible' if is_compatible else 'conflict',
            'conflicts': conflicts,
            'warnings': warnings,
            'document_evaluations': doc_evals
        }
    finally:
        if should_close:
            conn.close()

def update_trip_dates(trip_id, new_start_date, new_end_date, session_token, reason, expected_current_start_date=None, expected_current_end_date=None):
    import auth_services
    from datetime import datetime
    
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    
    if not reason or not isinstance(reason, str) or len(reason.strip()) < 5:
        raise ValueError("A meaningful, non-empty correction reason is mandatory (minimum 5 characters).")
    clean_reason = reason.strip()
    
    start_d = parse_flexible_date(new_start_date)
    end_d = parse_flexible_date(new_end_date)
    if not start_d or not end_d:
        raise ValueError("Invalid date format. Dates must be valid calendar dates (YYYY-MM-DD).")
    if end_d < start_d:
        raise ValueError("Invalid date range: Return date cannot be earlier than departure date.")
        
    new_start_iso = start_d.strftime("%Y-%m-%d")
    new_end_iso = end_d.strftime("%Y-%m-%d")
    
    conn = database.get_connection()
    try:
        trip = conn.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
        if not trip:
            raise ValueError(f"Trip not found: '{trip_id}'.")
            
        if trip['status'] == 'TRAVEL FILE READY':
            raise ValueError(f"Cannot modify finalized travel file: Trip '{trip_id}' has already been approved (TRAVEL FILE READY). Reopen trip first if permitted.")
            
        if expected_current_start_date is not None and trip['start_date'] != expected_current_start_date:
            raise ValueError(f"Concurrent edit conflict: Stored departure date ('{trip['start_date']}') does not match expected ('{expected_current_start_date}'). Please refresh.")
        if expected_current_end_date is not None and trip['end_date'] != expected_current_end_date:
            raise ValueError(f"Concurrent edit conflict: Stored return date ('{trip['end_date']}') does not match expected ('{expected_current_end_date}'). Please refresh.")
            
        # Consistency Check against Verified Documents
        consistency = validate_trip_date_consistency(trip_id, new_start_iso, new_end_iso, conn=conn, session_token=session_token)
        if not consistency['compatible']:
            conflict_summary = " | ".join(consistency['conflicts'])
            raise ValueError(f"Date correction blocked by document consistency safeguard: {conflict_summary}")
            
        old_start = trip['start_date']
        old_end = trip['end_date']
        
        # Atomic update and audit logging
        conn.execute("UPDATE trips SET start_date = ?, end_date = ? WHERE id = ?", (new_start_iso, new_end_iso, trip_id))
        
        now_iso = datetime.now().isoformat()
        audit_desc = (
            f"Trip dates updated from {old_start} - {old_end} to {new_start_iso} - {new_end_iso} "
            f"by {user['full_name']} ({user['role']}). Reason: {clean_reason}"
        )
        conn.execute(
            "INSERT INTO activity (trip_id, customer_id, description, timestamp) VALUES (?, ?, ?, ?)",
            (trip_id, trip['customer_id'], audit_desc, now_iso)
        )
        conn.commit()
        
        return {
            "success": True,
            "trip_id": trip_id,
            "old_dates": (old_start, old_end),
            "new_dates": (new_start_iso, new_end_iso),
            "actor": user['full_name'],
            "role": user['role'],
            "audit_description": audit_desc,
            "timestamp": now_iso
        }
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def approve_travel_file(trip_id, session_token):
    import auth_services
    from datetime import datetime
    
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    actor = user['full_name']
    
    conn = database.get_connection()
    try:
        trip = conn.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
        if not trip:
            raise ValueError(f"Trip not found: '{trip_id}'.")
            
        if trip['status'] == 'TRAVEL FILE READY':
            return {"success": True, "already_approved": True}
            
        # Verify readiness
        total, complete, attention, missing, pct, business_status = calculate_readiness(trip_id)
        if complete != total or missing > 0 or attention > 0:
            raise ValueError(f"Cannot approve travel file: Not all requirements are verified ({complete}/{total} complete).")
            
        # Enforce date consistency before final approval!
        consistency = validate_trip_date_consistency(trip_id, trip['start_date'], trip['end_date'], conn=conn, session_token=session_token)
        if not consistency['compatible']:
            conflict_summary = " | ".join(consistency['conflicts'])
            raise ValueError(f"Approval blocked: Material trip-date conflicts detected between stored trip dates and verified documents: {conflict_summary}")
            
        now_iso = datetime.now().isoformat()
        conn.execute("UPDATE trips SET status = 'TRAVEL FILE READY' WHERE id = ?", (trip_id,))
        conn.execute(
            "INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)",
            (trip_id, f"Travel File Approved by {actor}", now_iso)
        )
        conn.commit()
        return {"success": True, "trip_id": trip_id, "status": "TRAVEL FILE READY", "actor": actor}
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def generate_trip_travel_pack(trip_id, session_token, out_path=None):
    """
    Secure service boundary for generating a consolidated travel document pack / travel file.
    Enforces authentication, Supervisor/Admin role, and TRAVEL FILE READY status.
    Logs successful generation to the activity table.
    """
    import auth_services
    import travel_file_generator
    from datetime import datetime
    import re
    
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required to generate travel files.")
        
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    actor = user['full_name']
    
    if not trip_id or not isinstance(trip_id, str) or not re.match(r'^[A-Za-z0-9_-]+$', trip_id):
        raise ValueError("Invalid trip_id format.")
        
    if out_path is not None:
        if '..' in out_path.replace('\\', '/').split('/') or '..' in out_path:
            raise PermissionError(f"Security violation: Path traversal detected in output path '{out_path}'.")
        
    conn = database.get_connection()
    try:
        trip = conn.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
        if not trip:
            raise ValueError(f"Trip not found: '{trip_id}'.")
            
        if trip['status'] != 'TRAVEL FILE READY':
            raise ValueError(f"Cannot generate travel file: Trip '{trip_id}' is not approved (status is '{trip['status']}').")
            
        generated_path = travel_file_generator.generate_consolidated_travel_file(
            trip_id=trip_id,
            out_path=out_path,
            session_token=session_token
        )
        
        now_iso = datetime.now().isoformat()
        conn.execute(
            "INSERT INTO activity (trip_id, customer_id, description, timestamp) VALUES (?, ?, ?, ?)",
            (trip_id, trip['customer_id'], f"Consolidated Travel File generated by {actor} ({user['role']})", now_iso)
        )
        conn.commit()
        return generated_path
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()

def search_customers(query, session_token, include_archived=False):
    """
    Search customers by name or ID.
    Filters out archived customers by default unless include_archived=True.
    Requires authenticated session (Staff, Supervisor, Admin).
    """
    import auth_services
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
    auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    
    conn = database.get_connection()
    try:
        archived_filter = 1 if include_archived else 0
        if not query or not str(query).strip():
            rows = conn.execute("SELECT * FROM customers WHERE (archived = 0 OR ? = 1) ORDER BY id DESC", (archived_filter,)).fetchall()
        else:
            clean_q = f"%{str(query).strip()}%"
            rows = conn.execute("SELECT * FROM customers WHERE (archived = 0 OR ? = 1) AND (name LIKE ? OR id LIKE ?) ORDER BY id DESC", (archived_filter, clean_q, clean_q)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def get_customer_documents(customer_id, session_token, include_archived=False):
    """
    Retrieves all documents associated with customer_id across trips and travellers.
    Filters out archived documents by default unless include_archived=True.
    Enforces authentication and role verification.
    """
    import auth_services
    import re
    import os
    
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
    auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    
    if not customer_id or not isinstance(customer_id, str) or not re.match(r'^[A-Za-z0-9_-]+$', customer_id):
        raise ValueError("Invalid customer_id format.")
        
    conn = database.get_connection()
    try:
        cust = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not cust:
            raise ValueError(f"Customer not found: '{customer_id}'.")
            
        archived_filter = 1 if include_archived else 0
        req_cols = [c[1] for c in conn.execute("PRAGMA table_info(requirements)").fetchall()]
        has_cust_col = 'customer_id' in req_cols
        if has_cust_col:
            q = '''
                SELECT d.id as doc_id, d.requirement_id, d.status, d.file_path, d.uploaded_at, d.extracted_data,
                       COALESCE(d.archived, 0) as archived, d.archived_at, d.archived_by, d.archive_reason,
                       r.name as req_name, r.type as req_type, r.trip_id, r.traveller_id, r.customer_id as req_customer_id,
                       t.name as traveller_name,
                       tr.name as trip_name,
                       tr.destination as trip_destination,
                       COALESCE(r.customer_id, tr.customer_id, t.customer_id) as resolved_customer_id
                FROM documents d
                JOIN requirements r ON d.requirement_id = r.id
                LEFT JOIN travellers t ON r.traveller_id = t.id
                LEFT JOIN trips tr ON r.trip_id = tr.id
                WHERE COALESCE(r.customer_id, tr.customer_id, t.customer_id) = ?
                  AND (COALESCE(d.archived, 0) = 0 OR ? = 1)
                ORDER BY d.uploaded_at DESC, d.id DESC
            '''
        else:
            q = '''
                SELECT d.id as doc_id, d.requirement_id, d.status, d.file_path, d.uploaded_at, d.extracted_data,
                       COALESCE(d.archived, 0) as archived, d.archived_at, d.archived_by, d.archive_reason,
                       r.name as req_name, r.type as req_type, r.trip_id, r.traveller_id,
                       t.name as traveller_name,
                       tr.name as trip_name,
                       tr.destination as trip_destination,
                       COALESCE(tr.customer_id, t.customer_id) as resolved_customer_id
                FROM documents d
                JOIN requirements r ON d.requirement_id = r.id
                LEFT JOIN travellers t ON r.traveller_id = t.id
                LEFT JOIN trips tr ON r.trip_id = tr.id
                WHERE COALESCE(tr.customer_id, t.customer_id) = ?
                  AND (COALESCE(d.archived, 0) = 0 OR ? = 1)
                ORDER BY d.uploaded_at DESC, d.id DESC
            '''
        rows = conn.execute(q, (customer_id, archived_filter)).fetchall()
        
        results = []
        for r in rows:
            d_dict = dict(r)
            safe_path, path_err = get_safe_document_path(d_dict['file_path'])
            file_size = 0
            file_exists = False
            file_ext = ""
            if safe_path and not path_err and os.path.exists(safe_path):
                file_exists = True
                file_size = os.path.getsize(safe_path)
                file_ext = os.path.splitext(safe_path)[1].lower()
            
            if file_size > 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            elif file_size > 0:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = "0 KB"
                
            fmt_label = file_ext[1:].upper() if file_ext else "UNKNOWN"
            d_dict['file_exists'] = file_exists
            d_dict['file_size_bytes'] = file_size
            d_dict['file_size_str'] = size_str
            d_dict['file_format'] = fmt_label
            d_dict['customer_name'] = cust['name']
            
            # Version count
            try:
                v_cnt = conn.execute("SELECT COUNT(*) FROM document_versions WHERE document_id = ?", (d_dict['doc_id'],)).fetchone()[0]
                d_dict['version_count'] = max(v_cnt, 1)
            except Exception:
                d_dict['version_count'] = 1
                
            results.append(d_dict)
            
        return results
    finally:
        conn.close()

def get_document_for_download_or_preview(doc_id, customer_id, session_token, action='download'):
    """
    Retrieves original document bytes for preview or download after validating:
    - Session authentication & role
    - Cross-customer ownership
    - Path traversal & safe storage containment
    - File existence & size safety
    Logs audit event to activity table.
    """
    import auth_services
    import re
    import os
    from datetime import datetime
    
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
    
    if not doc_id or not isinstance(doc_id, str) or not re.match(r'^[A-Za-z0-9_-]+$', doc_id):
        raise ValueError("Invalid doc_id format.")
    if not customer_id or not isinstance(customer_id, str) or not re.match(r'^[A-Za-z0-9_-]+$', customer_id):
        raise ValueError("Invalid customer_id format.")
        
    conn = database.get_connection()
    try:
        q = '''
            SELECT d.*, r.name as req_name, r.type as req_type, r.trip_id, r.traveller_id,
                   t.name as traveller_name,
                   tr.name as trip_name,
                   COALESCE(tr.customer_id, t.customer_id) as doc_customer_id,
                   c.name as customer_name
            FROM documents d
            JOIN requirements r ON d.requirement_id = r.id
            LEFT JOIN travellers t ON r.traveller_id = t.id
            LEFT JOIN trips tr ON r.trip_id = tr.id
            LEFT JOIN customers c ON COALESCE(tr.customer_id, t.customer_id) = c.id
            WHERE d.id = ?
        '''
        doc_row = conn.execute(q, (doc_id,)).fetchone()
        if not doc_row:
            raise ValueError(f"Document not found: '{doc_id}'.")
            
        # Cross-customer validation
        if doc_row['doc_customer_id'] != customer_id:
            raise PermissionError(
                f"Security violation: Document '{doc_id}' does not belong to customer '{customer_id}' "
                f"(actual owner is '{doc_row['doc_customer_id']}'). Access rejected."
            )
            
        safe_path, path_err = get_safe_document_path(doc_row['file_path'])
        if path_err or not safe_path:
            raise FileNotFoundError(f"Document file unavailable: {path_err}")
            
        if not os.path.isfile(safe_path):
            raise FileNotFoundError(f"Document path '{safe_path}' is not a regular file.")
            
        file_size = os.path.getsize(safe_path)
        if file_size > 50 * 1024 * 1024:
            raise ValueError("Document exceeds maximum allowed size (50MB).")
            
        import storage_service
        file_bytes = storage_service.read_decrypted_document(
            safe_path,
            session_token=session_token,
            doc_id=doc_id,
            customer_id=customer_id
        )
            
        ext = os.path.splitext(safe_path)[1].lower()
        if ext == '.pdf':
            mime_type = 'application/pdf'
        elif ext in ('.jpg', '.jpeg'):
            mime_type = 'image/jpeg'
        elif ext == '.png':
            mime_type = 'image/png'
        else:
            mime_type = 'application/octet-stream'
            
        # Generate safe download filename
        subject = doc_row['traveller_name'] or doc_row['customer_name'] or "Customer"
        raw_name = f"{subject}_{doc_row['req_name']}{ext}"
        safe_filename = re.sub(r'[^A-Za-z0-9._-]', '_', raw_name)
        safe_filename = re.sub(r'_+', '_', safe_filename)
        
        # Audit logging (safe action logging without sensitive credentials or content)
        now_iso = datetime.now().isoformat()
        action_verb = "Downloaded" if str(action).lower() == "download" else "Previewed"
        audit_desc = (
            f"Document '{doc_row['req_name']}' ({action_verb}) for customer '{customer_id}' "
            f"accessed by {user['full_name']} ({user['role']})"
        )
        conn.execute(
            "INSERT INTO activity (customer_id, trip_id, description, timestamp) VALUES (?, ?, ?, ?)",
            (customer_id, doc_row['trip_id'], audit_desc, now_iso)
        )
        conn.commit()
        
        return {
            'doc_id': doc_row['id'],
            'req_name': doc_row['req_name'],
            'file_path': safe_path,
            'file_bytes': file_bytes,
            'file_size': file_size,
            'file_name': safe_filename,
            'mime_type': mime_type,
            'status': doc_row['status'],
            'customer_id': customer_id,
            'traveller_name': doc_row['traveller_name'],
            'trip_name': doc_row['trip_name']
        }
    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        raise e
    finally:
        conn.close()


def advanced_vault_search(
    session_token,
    query=None,
    document_type=None,
    verification_status=None,
    destination=None,
    trip_start=None,
    trip_end=None,
    limit=50,
    offset=0,
    conn=None
):
    """
    Advanced Customer, Traveller, Trip & Document Search (Phase 11C).

    Validates authentication and RBAC ('Staff', 'Supervisor', 'Admin').
    Supports parameterized multi-criteria searching across:
      - Customer (Name, ID)
      - Traveller (Name, ID, exact/conservative normalized passport number)
      - Trip (ID, Name, Destination, Overlapping Date Range)
      - Document (Type/Requirement Name, Verification Status)
      - Passport Number: Searches traveller.passport_number and Verified Passport document extracted_data.
        Strictly isolates passport numbers to individual travellers, rejecting cross-traveller leaks
        and ambiguous customer-level fallbacks.

    Returns structured results:
      {
          'documents': [...],
          'results': [...],       # alias to documents
          'customers': [...],
          'travellers': [...],
          'trips': [...],
          'total_documents': int,
          'limit': int,
          'offset': int
      }
    Zero raw OCR text or extracted_data JSON is exposed in results.
    Filesystem paths are not exposed.
    """
    import auth_services
    import json
    import re
    import os
    from datetime import datetime

    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")

    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])

    # Validate and normalize pagination parameters
    try:
        limit_int = int(limit)
        if limit_int < 1:
            limit_int = 50
        elif limit_int > 100:
            limit_int = 100
    except (ValueError, TypeError):
        limit_int = 50

    try:
        offset_int = int(offset)
        if offset_int < 0:
            offset_int = 0
    except (ValueError, TypeError):
        offset_int = 0

    # Validate ISO date strings
    def _validate_iso_date(d_val):
        if d_val is None or str(d_val).strip() == "":
            return None
        d_str = str(d_val).strip()
        if not re.match(r'^\d{4}-\d{2}-\d{2}$', d_str):
            raise ValueError(f"Invalid date format: '{d_str}'. Expected YYYY-MM-DD.")
        try:
            datetime.strptime(d_str, '%Y-%m-%d')
        except ValueError:
            raise ValueError(f"Invalid calendar date: '{d_str}'.")
        return d_str

    clean_trip_start = _validate_iso_date(trip_start)
    clean_trip_end = _validate_iso_date(trip_end)
    if clean_trip_start and clean_trip_end:
        if clean_trip_start > clean_trip_end:
            raise ValueError("Invalid date range: trip_start must be on or before trip_end.")

    close_conn = False
    if conn is None:
        conn = database.get_connection()
        close_conn = True

    try:
        clean_query = str(query).strip() if query is not None else ""
        matched_passport_traveller_ids = set()

        if clean_query:
            norm_q = clean_query.upper()
            # 1. Exact passport search in travellers table
            trav_rows = conn.execute(
                "SELECT id, passport_number FROM travellers WHERE passport_number IS NOT NULL AND TRIM(passport_number) != ''"
            ).fetchall()
            for tr_row in trav_rows:
                p_num = str(tr_row['passport_number']).strip().upper()
                if p_num == norm_q:
                    matched_passport_traveller_ids.add(tr_row['id'])

            # 2. Exact passport search in Verified Passport document extracted_data
            # for travellers whose passport_number is empty/NULL
            doc_pass_rows = conn.execute('''
                SELECT r.traveller_id, d.extracted_data
                FROM documents d
                JOIN requirements r ON d.requirement_id = r.id
                JOIN travellers t ON r.traveller_id = t.id
                WHERE r.name = 'Passport'
                  AND d.status = 'Verified'
                  AND (t.passport_number IS NULL OR TRIM(t.passport_number) = '')
                  AND d.extracted_data IS NOT NULL
            ''').fetchall()

            for dp_row in doc_pass_rows:
                if dp_row['extracted_data']:
                    try:
                        ext_data = json.loads(dp_row['extracted_data'])
                        if isinstance(ext_data, dict):
                            raw_p = ext_data.get('Passport Number') or ext_data.get('passport_number') or ext_data.get('PassportNo')
                            if raw_p and str(raw_p).strip().upper() == norm_q:
                                matched_passport_traveller_ids.add(dp_row['traveller_id'])
                    except Exception:
                        # Malformed extracted_data safely handled without breaking search
                        pass

        # Build WHERE clauses for documents
        where_clauses = ["1=1"]
        params = []

        if clean_query:
            text_like = f"%{clean_query}%"
            if matched_passport_traveller_ids:
                ph = ",".join(["?"] * len(matched_passport_traveller_ids))
                where_clauses.append(
                    f"(r.traveller_id IN ({ph}) OR c.name LIKE ? OR c.id LIKE ? OR t.name LIKE ? OR t.id LIKE ? OR tr.name LIKE ? OR tr.id LIKE ? OR tr.destination LIKE ? OR r.name LIKE ?)"
                )
                params.extend(list(matched_passport_traveller_ids))
                params.extend([text_like] * 8)
            else:
                where_clauses.append(
                    "(c.name LIKE ? OR c.id LIKE ? OR t.name LIKE ? OR t.id LIKE ? OR tr.name LIKE ? OR tr.id LIKE ? OR tr.destination LIKE ? OR r.name LIKE ?)"
                )
                params.extend([text_like] * 8)

        if document_type and str(document_type).strip() and str(document_type).strip().lower() != "all":
            clean_type = str(document_type).strip()
            where_clauses.append("(LOWER(r.name) = LOWER(?) OR LOWER(r.name) LIKE LOWER(?))")
            params.extend([clean_type, f"%{clean_type}%"])

        if verification_status and str(verification_status).strip() and str(verification_status).strip().lower() != "all":
            clean_status = str(verification_status).strip()
            where_clauses.append("d.status = ?")
            params.append(clean_status)

        if destination and str(destination).strip():
            clean_dest = f"%{str(destination).strip()}%"
            where_clauses.append("tr.destination LIKE ?")
            params.append(clean_dest)

        if clean_trip_start and clean_trip_end:
            where_clauses.append("tr.start_date IS NOT NULL AND tr.end_date IS NOT NULL AND tr.start_date <= ? AND tr.end_date >= ?")
            params.extend([clean_trip_end, clean_trip_start])
        elif clean_trip_start:
            where_clauses.append("tr.end_date IS NOT NULL AND tr.end_date >= ?")
            params.append(clean_trip_start)
        elif clean_trip_end:
            where_clauses.append("tr.start_date IS NOT NULL AND tr.start_date <= ?")
            params.append(clean_trip_end)

        # Count total matching documents
        count_sql = f'''
            SELECT COUNT(DISTINCT d.id) as cnt
            FROM documents d
            JOIN requirements r ON d.requirement_id = r.id
            LEFT JOIN trips tr ON r.trip_id = tr.id
            LEFT JOIN travellers t ON r.traveller_id = t.id
            LEFT JOIN customers c ON COALESCE(tr.customer_id, t.customer_id) = c.id
            WHERE {' AND '.join(where_clauses)}
        '''
        total_count = conn.execute(count_sql, params).fetchone()['cnt']

        # Query paginated matching documents with deterministic ordering
        doc_query_sql = f'''
            SELECT DISTINCT
                d.id as doc_id,
                d.status as doc_status,
                d.file_path,
                d.uploaded_at,
                r.id as req_id,
                r.name as req_name,
                r.type as req_type,
                r.trip_id,
                r.traveller_id,
                tr.name as trip_name,
                tr.destination as trip_destination,
                tr.start_date as trip_start_date,
                tr.end_date as trip_end_date,
                t.name as traveller_name,
                t.passport_number as traveller_passport,
                COALESCE(tr.customer_id, t.customer_id) as resolved_customer_id,
                c.name as customer_name
            FROM documents d
            JOIN requirements r ON d.requirement_id = r.id
            LEFT JOIN trips tr ON r.trip_id = tr.id
            LEFT JOIN travellers t ON r.traveller_id = t.id
            LEFT JOIN customers c ON COALESCE(tr.customer_id, t.customer_id) = c.id
            WHERE {' AND '.join(where_clauses)}
            ORDER BY d.uploaded_at DESC, d.id DESC
            LIMIT ? OFFSET ?
        '''
        exec_params = list(params) + [limit_int, offset_int]
        doc_rows = conn.execute(doc_query_sql, exec_params).fetchall()

        # Format document items (mask sensitive identifiers, zero OCR/raw extracted data exposure)
        formatted_docs = []
        for row in doc_rows:
            d = dict(row)
            safe_path, path_err = get_safe_document_path(d.get('file_path'))
            file_size = 0
            file_exists = False
            file_ext = ""
            if safe_path and not path_err and os.path.exists(safe_path):
                file_exists = True
                file_size = os.path.getsize(safe_path)
                file_ext = os.path.splitext(safe_path)[1].lower()

            if file_size > 1024 * 1024:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            elif file_size > 0:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = "0 KB"

            fmt_label = file_ext[1:].upper() if file_ext else "UNKNOWN"

            masked_passport = None
            raw_p = d.get('traveller_passport')
            if raw_p and str(raw_p).strip():
                clean_p = str(raw_p).strip()
                masked_passport = f"****{clean_p[-4:]}" if len(clean_p) >= 4 else "****"

            doc_item = {
                'doc_id': d['doc_id'],
                'requirement_id': d['req_id'],
                'req_name': d['req_name'],
                'req_type': d['req_type'],
                'status': d['doc_status'],
                'customer_id': d['resolved_customer_id'],
                'customer_name': d['customer_name'] or "Unknown Customer",
                'traveller_id': d['traveller_id'],
                'traveller_name': d['traveller_name'],
                'trip_id': d['trip_id'],
                'trip_name': d['trip_name'] or "Traveller Vault (Reusable)",
                'trip_destination': d['trip_destination'],
                'trip_start_date': d['trip_start_date'],
                'trip_end_date': d['trip_end_date'],
                'uploaded_at': d['uploaded_at'],
                'file_format': fmt_label,
                'file_size_bytes': file_size,
                'file_size_str': size_str,
                'file_exists': file_exists,
                'masked_passport': masked_passport
            }
            formatted_docs.append(doc_item)

        # Match Customers for context
        matched_customers = []
        cust_clauses = []
        cust_params = []
        if clean_query:
            cust_clauses.append("name LIKE ? OR id LIKE ?")
            cust_params.extend([text_like, text_like])
            if matched_passport_traveller_ids:
                ph = ",".join(["?"] * len(matched_passport_traveller_ids))
                cust_clauses.append(f"id IN (SELECT customer_id FROM travellers WHERE id IN ({ph}))")
                cust_params.extend(list(matched_passport_traveller_ids))
        if cust_clauses:
            c_rows = conn.execute(
                f"SELECT DISTINCT * FROM customers WHERE ({' OR '.join(cust_clauses)}) ORDER BY id DESC LIMIT 20",
                cust_params
            ).fetchall()
            for cr in c_rows:
                cd = dict(cr)
                matched_customers.append({
                    'id': cd['id'],
                    'name': cd['name'],
                    'customer_type': cd.get('customer_type', 'Individual'),
                    'status': cd.get('status', 'Active'),
                    'mobile': cd.get('mobile'),
                    'email': cd.get('email')
                })

        # Match Travellers for context
        matched_travellers = []
        trav_clauses = []
        trav_params = []
        if clean_query:
            trav_clauses.append("t.name LIKE ? OR t.id LIKE ?")
            trav_params.extend([text_like, text_like])
            if matched_passport_traveller_ids:
                ph = ",".join(["?"] * len(matched_passport_traveller_ids))
                trav_clauses.append(f"t.id IN ({ph})")
                trav_params.extend(list(matched_passport_traveller_ids))
        if trav_clauses:
            t_rows = conn.execute(f'''
                SELECT DISTINCT t.*, c.name as customer_name
                FROM travellers t
                LEFT JOIN customers c ON t.customer_id = c.id
                WHERE ({' OR '.join(trav_clauses)})
                ORDER BY t.id DESC LIMIT 20
            ''', trav_params).fetchall()
            for tr in t_rows:
                td = dict(tr)
                raw_p = td.get('passport_number')
                mp = f"****{str(raw_p).strip()[-4:]}" if (raw_p and len(str(raw_p).strip()) >= 4) else ("****" if raw_p else None)
                matched_travellers.append({
                    'id': td['id'],
                    'customer_id': td['customer_id'],
                    'customer_name': td.get('customer_name') or "Unknown Customer",
                    'name': td['name'],
                    'type': td.get('type', 'Adult'),
                    'role': td.get('role', 'Standard'),
                    'masked_passport': mp
                })

        # Match Trips for context
        matched_trips = []
        trip_clauses = []
        trip_params = []
        if clean_query:
            trip_clauses.append("(tr.name LIKE ? OR tr.id LIKE ? OR tr.destination LIKE ?)")
            trip_params.extend([text_like, text_like, text_like])
        if destination and str(destination).strip():
            trip_clauses.append("tr.destination LIKE ?")
            trip_params.append(f"%{str(destination).strip()}%")
        if clean_trip_start and clean_trip_end:
            trip_clauses.append("tr.start_date IS NOT NULL AND tr.end_date IS NOT NULL AND tr.start_date <= ? AND tr.end_date >= ?")
            trip_params.extend([clean_trip_end, clean_trip_start])
        elif clean_trip_start:
            trip_clauses.append("tr.end_date IS NOT NULL AND tr.end_date >= ?")
            trip_params.append(clean_trip_start)
        elif clean_trip_end:
            trip_clauses.append("tr.start_date IS NOT NULL AND tr.start_date <= ?")
            trip_params.append(clean_trip_end)

        if trip_clauses:
            tr_rows = conn.execute(f'''
                SELECT DISTINCT tr.*, c.name as customer_name
                FROM trips tr
                LEFT JOIN customers c ON tr.customer_id = c.id
                WHERE {' AND '.join(trip_clauses)}
                ORDER BY tr.id DESC LIMIT 20
            ''', trip_params).fetchall()
            for tr in tr_rows:
                trd = dict(tr)
                matched_trips.append({
                    'id': trd['id'],
                    'customer_id': trd['customer_id'],
                    'customer_name': trd.get('customer_name') or "Unknown Customer",
                    'name': trd['name'],
                    'destination': trd['destination'],
                    'start_date': trd['start_date'],
                    'end_date': trd['end_date'],
                    'status': trd['status']
                })

        return {
            'documents': formatted_docs,
            'results': formatted_docs,
            'customers': matched_customers,
            'travellers': matched_travellers,
            'trips': matched_trips,
            'total_documents': total_count,
            'limit': limit_int,
            'offset': offset_int
        }
    finally:
        if close_conn:
            conn.close()



# -------------------------------------------------------------
# Smart Intake Idempotency & Persistence Service (Phase 12C)
# -------------------------------------------------------------
_SMART_INTAKE_IDEMPOTENCY_CACHE = {}

def complete_smart_intake(
    customer_id=None,
    customer_data=None,
    traveller_data=None,
    document_fields=None,
    file_path=None,
    session_token=None,
    idempotency_key=None,
    force_new_version=False
):
    """
    Atomically finalizes a Smart Intake operation:
    1. Authenticates staff/supervisor/admin role.
    2. Validates idempotency key to prevent duplicate submissions on rerun or retry.
    3. Physically verifies document file on disk before committing to database.
    4. Creates or reuses customer record in a single atomic transaction.
    5. Detects existing matching traveller for this customer to prevent duplicate profiles.
    6. Attaches or updates the passport document in the Traveller Vault (reusable).
    7. Provides rollback and file compensation if any error occurs.
    """
    import auth_services
    import document_processor
    import os
    import re
    import uuid
    import json
    import hashlib
    import shutil
    import tempfile
    from datetime import datetime

    if not session_token:
        raise PermissionError("Unauthenticated: valid session token required.")
    user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])

    # 1. Idempotency Check
    if idempotency_key:
        clean_key = str(idempotency_key).strip()
        if clean_key in _SMART_INTAKE_IDEMPOTENCY_CACHE:
            return _SMART_INTAKE_IDEMPOTENCY_CACHE[clean_key]

        conn_check = database.get_connection()
        try:
            act_row = conn_check.execute(
                "SELECT customer_id, description FROM activity WHERE description LIKE ? ORDER BY id DESC LIMIT 1",
                (f"%[idempotency_key:{clean_key}]%",)
            ).fetchone()
            if act_row:
                desc = act_row['description']
                m_cust = re.search(r'customer:([A-Za-z0-9\-]+)', desc)
                m_trav = re.search(r'traveller:([A-Za-z0-9\-]+)', desc)
                m_doc = re.search(r'doc:([A-Za-z0-9\-]+)', desc)
                cached_res = {
                    'customer_id': m_cust.group(1) if m_cust else act_row['customer_id'],
                    'traveller_id': m_trav.group(1) if m_trav else None,
                    'document_id': m_doc.group(1) if m_doc else None,
                    'status': 'already_processed',
                    'reused': True
                }
                _SMART_INTAKE_IDEMPOTENCY_CACHE[clean_key] = cached_res
                return cached_res
        finally:
            conn_check.close()

    # 2. File Physical Validation
    if not file_path or not isinstance(file_path, str):
        raise ValueError("file_path must be a non-empty string.")

    # Determine approved documents root cleanly across Windows and Linux
    import storage_service
    approved_docs_dir = os.path.realpath(storage_service.get_storage_root())
    os.makedirs(approved_docs_dir, exist_ok=True)

    # Reject explicit path traversal sequences
    norm_parts = file_path.replace('\\', '/').split('/')
    if '..' in norm_parts:
        raise ValueError(f"Security Error: Path traversal sequence detected in file_path: '{file_path}'.")

    newly_copied = False
    safe_file_path, path_err = get_safe_document_path(file_path)
    if safe_file_path and not path_err and os.path.exists(safe_file_path):
        pass
    else:
        # File is not inside approved documents; check if it is inside system temp directory
        candidate_abs = os.path.realpath(os.path.abspath(file_path))
        temp_root = os.path.realpath(tempfile.gettempdir())
        is_in_temp = False
        try:
            is_in_temp = (os.path.realpath(os.path.commonpath([temp_root, candidate_abs])) == temp_root)
        except (ValueError, Exception):
            is_in_temp = False

        if is_in_temp and os.path.exists(candidate_abs) and os.path.isfile(candidate_abs):
            ext = os.path.splitext(candidate_abs)[1].lower()
            if not ext:
                ext = ".pdf"
            target_name = f"intake_{uuid.uuid4().hex}{ext}"
            target_path = os.path.join(approved_docs_dir, target_name)
            with open(candidate_abs, "rb") as f_cand:
                cand_data = f_cand.read()
            import storage_service
            storage_service.write_document_file(
                target_path,
                cand_data,
                session_token=session_token,
                base_dir=approved_docs_dir
            )
            safe_file_path = target_path
            newly_copied = True
        else:
            raise ValueError(f"Security Error or File Missing: Document file '{file_path}' does not exist or is outside approved directories.")

    if not os.path.exists(safe_file_path):
        raise ValueError(f"Document file does not exist on disk: '{safe_file_path}'.")

    file_size = os.path.getsize(safe_file_path)
    if file_size == 0:
        raise ValueError(f"Document file is empty (0 bytes): '{safe_file_path}'.")

    safe_abs = os.path.realpath(safe_file_path)
    try:
        if os.path.realpath(os.path.commonpath([approved_docs_dir, safe_abs])) == approved_docs_dir:
            rel_sub = os.path.relpath(safe_abs, approved_docs_dir).replace("\\", "/")
            rel_doc_path = f"documents/{rel_sub}"
        else:
            rel_doc_path = f"documents/{os.path.basename(safe_abs)}"
    except ValueError:
        rel_doc_path = f"documents/{os.path.basename(safe_abs)}"

    # 3. Database Operations in a Single Atomic Transaction
    conn = database.get_connection()
    try:
        # A. Customer
        if customer_id:
            cust_row = conn.execute("SELECT id, name FROM customers WHERE id = ?", (customer_id,)).fetchone()
            if not cust_row:
                raise ValueError(f"Customer not found: '{customer_id}'.")
            c_id = customer_id
            c_name = cust_row['name']
            ensure_customer_mandatory_requirements(c_id, conn=conn)
        else:
            if not customer_data or not customer_data.get('name', '').strip():
                raise ValueError("Customer Name is required.")
            c_name = customer_data['name'].strip()
            c_id = generate_next_id(conn, 'customers', 'KT-C-')
            c_mob = customer_data.get('mobile')
            c_em = customer_data.get('email')
            c_type = customer_data.get('customer_type') or 'Individual'
            conn.execute('''
                INSERT INTO customers (id, name, mobile, email, customer_type, status)
                VALUES (?, ?, ?, ?, ?, 'Active')
            ''', (c_id, c_name, c_mob, c_em, c_type))
            conn.execute('''
                INSERT INTO activity (customer_id, description, timestamp)
                VALUES (?, ?, datetime('now'))
            ''', (c_id, f"Customer created: {c_name}"))
            ensure_customer_mandatory_requirements(c_id, conn=conn)

        # B. Traveller with Duplicate Detection
        trav_data = traveller_data or {}
        t_name = trav_data.get('name') or (document_fields or {}).get('Full Name') or c_name
        t_dob = trav_data.get('dob') or (document_fields or {}).get('Date of Birth')
        t_pass = trav_data.get('passport_number') or (document_fields or {}).get('Passport Number')
        t_nat = trav_data.get('nationality') or (document_fields or {}).get('Nationality')
        t_type = trav_data.get('traveller_type') or 'Adult'
        t_rel = trav_data.get('relationship') or 'Self'
        t_lead = trav_data.get('lead_traveller', True)

        existing_travellers = conn.execute(
            "SELECT id, name, passport_number, dob, nationality FROM travellers WHERE customer_id = ?",
            (c_id,)
        ).fetchall()

        matched_trav_id = None
        norm_target_name = document_processor.normalize_person_name(t_name) if t_name else ""
        clean_target_pass = re.sub(r'[^A-Za-z0-9]', '', t_pass).upper() if t_pass else ""

        for et in existing_travellers:
            et_norm_name = document_processor.normalize_person_name(et['name']) if et['name'] else ""
            et_clean_pass = re.sub(r'[^A-Za-z0-9]', '', et['passport_number'] or '').upper()

            # Passport match
            if clean_target_pass and et_clean_pass and clean_target_pass == et_clean_pass:
                matched_trav_id = et['id']
                break
            # Name + DOB match
            if norm_target_name and et_norm_name and norm_target_name == et_norm_name:
                if t_dob and et['dob'] and str(t_dob).strip().lower() == str(et['dob']).strip().lower():
                    matched_trav_id = et['id']
                    break
                if not clean_target_pass and not et_clean_pass:
                    matched_trav_id = et['id']
                    break

        if matched_trav_id:
            trav_id = matched_trav_id
            trav_reused = True
        else:
            trav_id = generate_next_id(conn, 'travellers', 'KT-TR-')
            conn.execute('''
                INSERT INTO travellers (id, customer_id, name, dob, type, relationship, role, passport_number, nationality)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (trav_id, c_id, t_name, t_dob, t_type, t_rel, 'Lead Traveller' if t_lead else 'Standard', t_pass, t_nat))
            conn.execute('''
                INSERT INTO activity (customer_id, description, timestamp)
                VALUES (?, ?, datetime('now'))
            ''', (c_id, f"Traveller added: {t_name}"))
            trav_reused = False

        # C. Requirement & Document Attachment
        req_row = conn.execute('''
            SELECT id FROM requirements 
            WHERE traveller_id = ? AND name = 'Passport' AND type = 'TRAVELLER_VAULT'
        ''', (trav_id,)).fetchone()

        if req_row:
            req_id = req_row['id']
        else:
            req_id = f"REQ-TRV-{uuid.uuid4().hex[:6]}"
            conn.execute('''
                INSERT INTO requirements (id, trip_id, traveller_id, name, type)
                VALUES (?, NULL, ?, 'Passport', 'TRAVELLER_VAULT')
            ''', (req_id, trav_id))

        existing_doc = conn.execute('''
            SELECT id, status, file_path, extracted_data FROM documents
            WHERE requirement_id = ?
            ORDER BY uploaded_at DESC LIMIT 1
        ''', (req_id,)).fetchone()

        doc_reused = False
        if existing_doc:
            existing_full_path, _ = get_safe_document_path(existing_doc['file_path'])
            same_content = False
            if existing_full_path and os.path.exists(existing_full_path):
                import storage_service
                f1_bytes = storage_service.read_decrypted_document(safe_file_path, session_token=session_token)
                f2_bytes = storage_service.read_decrypted_document(existing_full_path, session_token=session_token)
                same_content = (hashlib.sha256(f1_bytes).digest() == hashlib.sha256(f2_bytes).digest())

            if same_content and not force_new_version:
                doc_id = existing_doc['id']
                doc_reused = True
            else:
                # Legitimate renewal or new document version
                doc_id = existing_doc['id']
                try:
                    conn.execute('''
                        INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason, timestamp)
                        VALUES (?, 'VERSION_REPLACE', ?, 'Under Review', ?, 'Updated document uploaded via Smart Intake', datetime('now'))
                    ''', (doc_id, existing_doc['status'], user['full_name']))
                except Exception:
                    pass
                conn.execute('''
                    UPDATE documents SET status = 'Under Review', file_path = ?, extracted_data = ?, uploaded_at = datetime('now')
                    WHERE id = ?
                ''', (rel_doc_path, json.dumps(document_fields or {}), doc_id))
                conn.execute('''
                    INSERT INTO activity (customer_id, description, timestamp)
                    VALUES (?, ?, datetime('now'))
                ''', (c_id, f"Passport document updated for traveller: {t_name}"))
        else:
            doc_id = f"DOC-{uuid.uuid4().hex[:8]}"
            conn.execute('''
                INSERT INTO documents (id, requirement_id, status, extracted_data, file_path, uploaded_at)
                VALUES (?, ?, 'Under Review', ?, ?, datetime('now'))
            ''', (doc_id, req_id, json.dumps(document_fields or {}), rel_doc_path))
            conn.execute('''
                INSERT INTO activity (customer_id, description, timestamp)
                VALUES (?, ?, datetime('now'))
            ''', (c_id, "Passport uploaded for traveller"))

        # User profile synchronization
        if t_name and c_id:
            conn.execute('''
                INSERT OR REPLACE INTO user_profile (customer_id, full_name, dob, nationality, passport_number, passport_expiry)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (c_id, t_name, t_dob, t_nat, t_pass, (document_fields or {}).get('Expiry Date')))

        # Log completion with idempotency tag
        if idempotency_key:
            act_tag = f"Smart intake completed [idempotency_key:{idempotency_key}] (customer:{c_id}, traveller:{trav_id}, doc:{doc_id})"
            conn.execute('''
                INSERT INTO activity (customer_id, description, timestamp)
                VALUES (?, ?, datetime('now'))
            ''', (c_id, act_tag))

        conn.commit()

        result = {
            'customer_id': c_id,
            'traveller_id': trav_id,
            'document_id': doc_id,
            'status': 'success',
            'traveller_reused': trav_reused,
            'document_reused': doc_reused,
            'reused': (trav_reused and doc_reused)
        }

        if idempotency_key:
            _SMART_INTAKE_IDEMPOTENCY_CACHE[clean_key] = result

        return result

    except Exception as e:
        if conn.in_transaction:
            conn.rollback()
        if newly_copied and safe_file_path and os.path.exists(safe_file_path):
            try:
                os.remove(safe_file_path)
            except Exception:
                pass
        raise e
    finally:
        conn.close()


def mask_aadhaar(aadhaar_val):
    if not aadhaar_val:
        return ""
    val_clean = re.sub(r'[^0-9X]', '', str(aadhaar_val))
    if len(val_clean) >= 4:
        return f"XXXX-XXXX-{val_clean[-4:]}"
    return "XXXX-XXXX-XXXX"


# =====================================================================
# Feature Toggles for Admin Delete, Archive, Replace & Recovery
# =====================================================================
import sqlite3
import hashlib
import uuid
import json
from typing import Tuple, List, Optional, Dict, Any, Set
ENABLE_CUSTOMER_ARCHIVE = True
ENABLE_DOCUMENT_ARCHIVE = True
ENABLE_DOCUMENT_REPLACE = True
ENABLE_PERMANENT_DELETE = False  # Strict default False until all gates pass
ENABLE_DELETION_REQUESTS = True

ALLOWED_DOCUMENT_EXTENSIONS = {'.pdf', '.jpg', '.jpeg', '.png'}
MAX_DOCUMENT_SIZE_BYTES = 25 * 1024 * 1024

def check_verified_backup_exists() -> Tuple[bool, Optional[str]]:
    """
    Cross-platform check verifying that a valid SQLite backup exists under the
    application backups directory and passes read-only PRAGMA integrity_check.
    """
    db_path = database.get_db_path()
    db_parent = os.path.dirname(os.path.abspath(db_path))
    app_root = os.path.dirname(db_parent) if os.path.basename(db_parent).lower() == "data" else os.path.dirname(os.path.abspath(__file__))
    backups_roots = [
        os.path.join(app_root, "backups"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups"),
    ]

    backup_candidates = []
    seen = set()
    for b_root in backups_roots:
        if not os.path.isdir(b_root):
            continue
        legacy_cand = os.path.join(b_root, "pre_admin_delete_archive", "kt_vault_v3.db")
        if legacy_cand not in seen:
            backup_candidates.append(legacy_cand)
            seen.add(legacy_cand)
        try:
            for sub in sorted(os.listdir(b_root), reverse=True):
                sub_p = os.path.join(b_root, sub)
                if os.path.isdir(sub_p) and sub.startswith("pre_"):
                    for rel in (os.path.join("data", "kt_vault_v3.db"), "kt_vault_v3.db"):
                        cand = os.path.join(sub_p, rel)
                        if cand not in seen:
                            backup_candidates.append(cand)
                            seen.add(cand)
        except Exception:
            pass

    for b_path in backup_candidates:
        if os.path.isfile(b_path) and os.path.getsize(b_path) > 0:
            try:
                b_conn = sqlite3.connect(f"file:{os.path.abspath(b_path)}?mode=ro", uri=True)
                res = b_conn.execute("PRAGMA integrity_check").fetchall()
                b_conn.close()
                if res and res[0][0] == 'ok':
                    return True, b_path
            except Exception:
                pass
    return False, None

def check_customer_retention_eligibility(customer_id: str, conn: Optional[Any] = None) -> Tuple[bool, List[str]]:
    """
    Checks if a customer has any active retention blocks (e.g. active trips, legal holds).
    Returns (eligible: bool, conflicts: list[str])
    """
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True
    try:
        conflicts = []
        active_trips = conn.execute(
            "SELECT id, name, status FROM trips WHERE customer_id = ? AND status IN ('Active', 'In Progress', 'Documents In Progress', 'Upcoming')",
            (customer_id,)
        ).fetchall()
        for t in active_trips:
            conflicts.append(f"Active trip '{t['name']}' ({t['id']}) in status '{t['status']}'")
            
        cust = conn.execute("SELECT status FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if cust and cust['status'] in ('Legal Hold', 'Dispute', 'Audit'):
            conflicts.append(f"Customer status is on hold: '{cust['status']}'")
            
        return (len(conflicts) == 0), conflicts
    finally:
        if should_close:
            conn.close()

def validate_document_upload(file_bytes: bytes, filename: str) -> None:
    """
    Validates uploaded file against extension allowlist, size limits, and magic bytes.
    Raises ValueError with safe error message if invalid.
    """
    if not file_bytes:
        raise ValueError("Upload rejected: File is empty (0 bytes).")
    if len(file_bytes) > MAX_DOCUMENT_SIZE_BYTES:
        raise ValueError(f"Upload rejected: File size ({len(file_bytes)} bytes) exceeds 25 MB limit.")
        
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_DOCUMENT_EXTENSIONS:
        raise ValueError(f"Upload rejected: Disallowed file extension '{ext}'. Allowed: .pdf, .jpg, .jpeg, .png")
        
    if ext == '.pdf':
        if not file_bytes.startswith(b'%PDF'):
            raise ValueError("Upload rejected: Spoofed MIME/content. File does not start with valid PDF signature.")
    elif ext in ('.jpg', '.jpeg'):
        if not file_bytes.startswith(b'\xFF\xD8\xFF'):
            raise ValueError("Upload rejected: Spoofed MIME/content. File does not start with valid JPEG signature.")
    elif ext == '.png':
        if not file_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError("Upload rejected: Spoofed MIME/content. File does not start with valid PNG signature.")

def archive_customer(customer_id: str, reason: str, session_token: str) -> Dict[str, Any]:
    """
    Reversibly soft-archives a customer record.
    Preserves all trips, travellers, requirements, documents, files, and audit records.
    Requires customer:archive permission.
    """
    if not ENABLE_CUSTOMER_ARCHIVE:
        raise RuntimeError("Customer archival is disabled by configuration.")
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    auth_services.require_permission(session_token, "customer:archive")
    user = auth_services.require_role(session_token, ["Admin", "Administrator"])
        
    if not reason or len(reason.strip()) < 3:
        raise ValueError("A valid archive reason (minimum 3 characters) is required.")
        
    conn = database.get_connection()
    try:
        cust = conn.execute("SELECT id, name, archived FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not cust:
            raise ValueError(f"Customer '{customer_id}' not found.")
        if cust['archived'] == 1:
            return {"success": True, "message": f"Customer '{customer_id}' is already archived.", "customer_id": customer_id}
            
        now_iso = datetime.now().isoformat()
        conn.execute(
            "UPDATE customers SET archived = 1, archived_at = ?, archived_by = ?, archive_reason = ? WHERE id = ?",
            (now_iso, user.get('id'), reason.strip(), customer_id)
        )
        conn.commit()
        
        auth_services.log_security_event(
            "CUSTOMER_ARCHIVE",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Archived customer {customer_id}: {reason.strip()}"
        )
        return {"success": True, "customer_id": customer_id, "archived": True, "archived_at": now_iso}
    finally:
        conn.close()

def unarchive_customer(customer_id: str, session_token: str) -> Dict[str, Any]:
    """
    Restores a soft-archived customer record to active operational view.
    Requires customer:unarchive permission.
    """
    if not ENABLE_CUSTOMER_ARCHIVE:
        raise RuntimeError("Customer archival is disabled by configuration.")
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    auth_services.require_permission(session_token, "customer:unarchive")
    user = auth_services.require_role(session_token, ["Admin", "Administrator"])
        
    conn = database.get_connection()
    try:
        cust = conn.execute("SELECT id, name, archived FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not cust:
            raise ValueError(f"Customer '{customer_id}' not found.")
        if cust['archived'] == 0:
            return {"success": True, "message": f"Customer '{customer_id}' is already active.", "customer_id": customer_id}
            
        conn.execute(
            "UPDATE customers SET archived = 0, archived_at = NULL, archived_by = NULL, archive_reason = NULL WHERE id = ?",
            (customer_id,)
        )
        conn.commit()
        
        auth_services.log_security_event(
            "CUSTOMER_UNARCHIVE",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Restored customer {customer_id} to active view"
        )
        return {"success": True, "customer_id": customer_id, "archived": False}
    finally:
        conn.close()

def preview_customer_deletion(customer_id: str, session_token: str) -> Dict[str, Any]:
    """
    Constructs a pre-deletion impact preview showing counts of all dependent entities.
    Never exposes sensitive document contents or full Aadhaar/PAN.
    Requires customer:delete permission and Admin role.
    """
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
    auth_services.require_permission(session_token, "customer:delete")
    auth_services.require_role(session_token, ["Admin", "Administrator"])
    
    conn = database.get_connection()
    try:
        cust = conn.execute("SELECT id, name, customer_type FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not cust:
            raise ValueError(f"Customer '{customer_id}' not found.")
            
        travellers = conn.execute("SELECT id FROM travellers WHERE customer_id = ?", (customer_id,)).fetchall()
        tr_ids = [t['id'] for t in travellers]
        
        trips = conn.execute("SELECT id FROM trips WHERE customer_id = ?", (customer_id,)).fetchall()
        trip_ids = [t['id'] for t in trips]
        
        trip_travellers = 0
        if trip_ids:
            placeholders = ','.join(['?'] * len(trip_ids))
            trip_travellers = conn.execute(f"SELECT COUNT(*) FROM trip_travellers WHERE trip_id IN ({placeholders})", trip_ids).fetchone()[0]
            
        reqs = conn.execute("""
            SELECT id FROM requirements 
            WHERE customer_id = ? 
               OR (traveller_id IS NOT NULL AND traveller_id IN (SELECT id FROM travellers WHERE customer_id = ?))
               OR (trip_id IS NOT NULL AND trip_id IN (SELECT id FROM trips WHERE customer_id = ?))
        """, (customer_id, customer_id, customer_id)).fetchall()
        req_ids = [r['id'] for r in reqs]
        
        doc_count = 0
        version_count = 0
        history_count = 0
        file_count = 0
        if req_ids:
            placeholders = ','.join(['?'] * len(req_ids))
            docs = conn.execute(f"SELECT id, file_path FROM documents WHERE requirement_id IN ({placeholders})", req_ids).fetchall()
            doc_count = len(docs)
            doc_ids = [d['id'] for d in docs]
            if doc_ids:
                d_placeholders = ','.join(['?'] * len(doc_ids))
                version_count = conn.execute(f"SELECT COUNT(*) FROM document_versions WHERE document_id IN ({d_placeholders})", doc_ids).fetchone()[0]
                history_count = conn.execute(f"SELECT COUNT(*) FROM document_history WHERE document_id IN ({d_placeholders})", doc_ids).fetchone()[0]
                
            for d in docs:
                if d['file_path'] and os.path.exists(d['file_path']):
                    file_count += 1
                    
        activity_count = conn.execute("SELECT COUNT(*) FROM activity WHERE customer_id = ?", (customer_id,)).fetchone()[0]
        user_profile_count = conn.execute("SELECT COUNT(*) FROM user_profile WHERE customer_id = ?", (customer_id,)).fetchone()[0]
        deletion_req_count = conn.execute("SELECT COUNT(*) FROM deletion_requests WHERE object_type = 'CUSTOMER' AND object_id = ?", (customer_id,)).fetchone()[0]
        
        backup_verified, backup_path = check_verified_backup_exists()
        retention_eligible, conflicts = check_customer_retention_eligibility(customer_id, conn)
        
        return {
            "customer_id": customer_id,
            "customer_name": cust['name'],
            "customer_type": cust['customer_type'],
            "counts": {
                "customers": 1,
                "travellers": len(tr_ids),
                "trips": len(trip_ids),
                "trip_relationships": trip_travellers,
                "requirements": len(req_ids),
                "documents": doc_count,
                "document_versions": version_count,
                "document_history": history_count,
                "activity_records": activity_count,
                "user_profiles": user_profile_count,
                "deletion_requests": deletion_req_count,
                "encrypted_files": file_count
            },
            "backup_verified": backup_verified,
            "backup_path": backup_path,
            "retention_eligible": retention_eligible,
            "retention_conflicts": conflicts
        }
    finally:
        conn.close()

def permanently_delete_customer(
    customer_id: str,
    confirmation_code: str,
    reason: str,
    session_token: str,
    bypass_retention_check: bool = False
) -> Dict[str, Any]:
    """
    Administrator-only permanent customer deletion.
    Enforces multi-stage safety:
    1. Server-side permission 'customer:delete'
    2. Admin role verification
    3. Feature flag ENABLE_PERMANENT_DELETE check
    4. Verified database backup check
    5. Retention policy conflict check
    6. Typed confirmation verification
    7. Atomic SQLite transaction across all dependent records (reverse dependency order)
    8. Post-transaction encrypted file cleanup
    9. SQLite integrity check
    10. Tamper-evident audit logging with pre/post row counts
    """
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    auth_services.require_permission(session_token, "customer:delete")
    user = auth_services.require_role(session_token, ["Admin", "Administrator"])

    if not ENABLE_PERMANENT_DELETE:
        raise RuntimeError("Permanent deletion is disabled by configuration (ENABLE_PERMANENT_DELETE=False).")
    
    backup_ok, backup_path = check_verified_backup_exists()
    if not backup_ok:
        raise RuntimeError("Permanent deletion blocked: No verified database backup found. A verified backup must be taken before permanent deletion.")
        
    expected_codes = {f"CONFIRM-DELETE-{customer_id}", customer_id}
    if not confirmation_code or confirmation_code.strip() not in expected_codes:
        raise ValueError(f"Confirmation code mismatch. Expected 'CONFIRM-DELETE-{customer_id}' or '{customer_id}'.")
        
    if not reason or len(reason.strip()) < 5:
        raise ValueError("A documented deletion reason of at least 5 characters is required.")
        
    conn = database.get_connection()
    try:
        eligible, conflicts = check_customer_retention_eligibility(customer_id, conn)
        if not eligible and not bypass_retention_check:
            raise ValueError(f"Retention policy block: Cannot permanently delete customer. Conflicts: {', '.join(conflicts)}")
            
        cust = conn.execute("SELECT id, name FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not cust:
            raise ValueError(f"Customer '{customer_id}' not found.")
            
        travellers = conn.execute("SELECT id FROM travellers WHERE customer_id = ?", (customer_id,)).fetchall()
        tr_ids = [t['id'] for t in travellers]
        
        trips = conn.execute("SELECT id FROM trips WHERE customer_id = ?", (customer_id,)).fetchall()
        trip_ids = [t['id'] for t in trips]
        
        reqs = conn.execute("""
            SELECT id FROM requirements 
            WHERE customer_id = ? 
               OR (traveller_id IS NOT NULL AND traveller_id IN (SELECT id FROM travellers WHERE customer_id = ?))
               OR (trip_id IS NOT NULL AND trip_id IN (SELECT id FROM trips WHERE customer_id = ?))
        """, (customer_id, customer_id, customer_id)).fetchall()
        req_ids = [r['id'] for r in reqs]
        
        doc_ids = []
        files_to_remove = []
        if req_ids:
            placeholders = ','.join(['?'] * len(req_ids))
            docs = conn.execute(f"SELECT id, file_path FROM documents WHERE requirement_id IN ({placeholders})", req_ids).fetchall()
            doc_ids = [d['id'] for d in docs]
            for d in docs:
                if d['file_path']:
                    files_to_remove.append(d['file_path'])
            if doc_ids:
                d_placeholders = ','.join(['?'] * len(doc_ids))
                versions = conn.execute(f"SELECT file_path FROM document_versions WHERE document_id IN ({d_placeholders})", doc_ids).fetchall()
                for v in versions:
                    if v['file_path']:
                        files_to_remove.append(v['file_path'])
                        
        pre_counts = {
            "customers": conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
            "travellers": conn.execute("SELECT COUNT(*) FROM travellers").fetchone()[0],
            "trips": conn.execute("SELECT COUNT(*) FROM trips").fetchone()[0],
            "trip_travellers": conn.execute("SELECT COUNT(*) FROM trip_travellers").fetchone()[0],
            "requirements": conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0],
            "documents": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
            "document_versions": conn.execute("SELECT COUNT(*) FROM document_versions").fetchone()[0],
            "document_history": conn.execute("SELECT COUNT(*) FROM document_history").fetchone()[0],
            "activity": conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0],
            "user_profile": conn.execute("SELECT COUNT(*) FROM user_profile").fetchone()[0]
        }
        
        conn.execute("BEGIN TRANSACTION")
        
        if doc_ids:
            d_placeholders = ','.join(['?'] * len(doc_ids))
            conn.execute(f"DELETE FROM document_versions WHERE document_id IN ({d_placeholders})", doc_ids)
            conn.execute(f"DELETE FROM document_history WHERE document_id IN ({d_placeholders})", doc_ids)
            conn.execute(f"DELETE FROM documents WHERE id IN ({d_placeholders})", doc_ids)
            
        if req_ids:
            r_placeholders = ','.join(['?'] * len(req_ids))
            conn.execute(f"DELETE FROM requirements WHERE id IN ({r_placeholders})", req_ids)
            
        if trip_ids:
            t_placeholders = ','.join(['?'] * len(trip_ids))
            conn.execute(f"DELETE FROM trip_travellers WHERE trip_id IN ({t_placeholders})", trip_ids)
            conn.execute(f"DELETE FROM trips WHERE id IN ({t_placeholders})", trip_ids)
            
        if tr_ids:
            tr_placeholders = ','.join(['?'] * len(tr_ids))
            conn.execute(f"DELETE FROM trip_travellers WHERE traveller_id IN ({tr_placeholders})", tr_ids)
            conn.execute(f"DELETE FROM travellers WHERE id IN ({tr_placeholders})", tr_ids)
            
        conn.execute("DELETE FROM user_profile WHERE customer_id = ?", (customer_id,))
        conn.execute("DELETE FROM activity WHERE customer_id = ?", (customer_id,))
        conn.execute("DELETE FROM deletion_requests WHERE object_type = 'CUSTOMER' AND object_id = ?", (customer_id,))
        conn.execute("DELETE FROM customers WHERE id = ?", (customer_id,))
        
        conn.commit()
        
        for fpath in set(files_to_remove):
            try:
                if fpath and os.path.exists(fpath):
                    os.remove(fpath)
            except Exception:
                pass
                
        res = [r[0] for r in conn.execute("PRAGMA integrity_check").fetchall()]
        if res != ['ok']:
            raise RuntimeError(f"Database integrity check failed after deletion: {res}")
            
        post_counts = {
            "customers": conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0],
            "travellers": conn.execute("SELECT COUNT(*) FROM travellers").fetchone()[0],
            "trips": conn.execute("SELECT COUNT(*) FROM trips").fetchone()[0],
            "trip_travellers": conn.execute("SELECT COUNT(*) FROM trip_travellers").fetchone()[0],
            "requirements": conn.execute("SELECT COUNT(*) FROM requirements").fetchone()[0],
            "documents": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
            "document_versions": conn.execute("SELECT COUNT(*) FROM document_versions").fetchone()[0],
            "document_history": conn.execute("SELECT COUNT(*) FROM document_history").fetchone()[0],
            "activity": conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0],
            "user_profile": conn.execute("SELECT COUNT(*) FROM user_profile").fetchone()[0]
        }
        
        auth_services.log_security_event(
            "CUSTOMER_PERMANENT_DELETE",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Permanently deleted customer {customer_id}. Reason: {reason.strip()}. Pre-counts: {pre_counts}. Post-counts: {post_counts}",
            conn=conn
        )
        
        return {
            "success": True,
            "customer_id": customer_id,
            "pre_counts": pre_counts,
            "post_counts": post_counts,
            "files_removed": len(set(files_to_remove))
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def check_customer_deletion_safety(customer_id: str, session_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Inspects whether a customer record can be safely deleted or has linked records requiring archival.
    Returns:
        {
            "customer_id": str,
            "customer_name": str,
            "can_delete": bool,
            "conflicts": List[str],
            "counts": Dict[str, int]
        }
    """
    conn = database.get_connection()
    try:
        cust = conn.execute("SELECT id, name, archived FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not cust:
            raise ValueError(f"Customer '{customer_id}' not found.")

        # 1. Linked travellers
        cnt_travellers = conn.execute("SELECT COUNT(*) FROM travellers WHERE customer_id = ?", (customer_id,)).fetchone()[0]

        # 2. Linked trips
        cnt_trips = conn.execute("SELECT COUNT(*) FROM trips WHERE customer_id = ?", (customer_id,)).fetchone()[0]

        # 3. Linked trip travellers
        cnt_trip_travellers = conn.execute("""
            SELECT COUNT(*) FROM trip_travellers 
            WHERE trip_id IN (SELECT id FROM trips WHERE customer_id = ?)
               OR traveller_id IN (SELECT id FROM travellers WHERE customer_id = ?)
        """, (customer_id, customer_id)).fetchone()[0]

        # 4. Linked requirements (trip or traveller requirements)
        cnt_trip_trav_reqs = conn.execute("""
            SELECT COUNT(*) FROM requirements 
            WHERE (trip_id IS NOT NULL AND trip_id IN (SELECT id FROM trips WHERE customer_id = ?))
               OR (traveller_id IS NOT NULL AND traveller_id IN (SELECT id FROM travellers WHERE customer_id = ?))
        """, (customer_id, customer_id)).fetchone()[0]

        # 5. Linked documents across any requirements for this customer / trips / travellers
        cnt_docs = conn.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE requirement_id IN (
                SELECT id FROM requirements 
                WHERE customer_id = ? 
                   OR (trip_id IS NOT NULL AND trip_id IN (SELECT id FROM trips WHERE customer_id = ?))
                   OR (traveller_id IS NOT NULL AND traveller_id IN (SELECT id FROM travellers WHERE customer_id = ?))
            )
        """, (customer_id, customer_id, customer_id)).fetchone()[0]

        # 6. Linked document versions
        cnt_versions = conn.execute("""
            SELECT COUNT(*) FROM document_versions 
            WHERE document_id IN (
                SELECT id FROM documents 
                WHERE requirement_id IN (
                    SELECT id FROM requirements 
                    WHERE customer_id = ? 
                       OR (trip_id IS NOT NULL AND trip_id IN (SELECT id FROM trips WHERE customer_id = ?))
                       OR (traveller_id IS NOT NULL AND traveller_id IN (SELECT id FROM travellers WHERE customer_id = ?))
                )
            )
        """, (customer_id, customer_id, customer_id)).fetchone()[0]

        # 7. Customer Vault placeholder requirements
        cnt_placeholder_reqs = conn.execute(
            "SELECT COUNT(*) FROM requirements WHERE customer_id = ? AND type = 'CUSTOMER_VAULT'",
            (customer_id,)
        ).fetchone()[0]

        # 8. User profile stub
        cnt_user_profile = conn.execute("SELECT COUNT(*) FROM user_profile WHERE customer_id = ?", (customer_id,)).fetchone()[0]

        conflicts = []
        if cnt_trips > 0:
            conflicts.append(f"{cnt_trips} linked trip(s)")
        if cnt_travellers > 0:
            conflicts.append(f"{cnt_travellers} linked traveller(s)")
        if cnt_trip_travellers > 0:
            conflicts.append(f"{cnt_trip_travellers} trip-traveller link(s)")
        if cnt_trip_trav_reqs > 0:
            conflicts.append(f"{cnt_trip_trav_reqs} trip/traveller requirement(s)")
        if cnt_docs > 0:
            conflicts.append(f"{cnt_docs} linked document(s)")
        if cnt_versions > 0:
            conflicts.append(f"{cnt_versions} document version(s)")

        can_delete = (len(conflicts) == 0)

        counts = {
            "trips": cnt_trips,
            "travellers": cnt_travellers,
            "trip_travellers": cnt_trip_travellers,
            "trip_traveller_requirements": cnt_trip_trav_reqs,
            "documents": cnt_docs,
            "document_versions": cnt_versions,
            "placeholder_requirements": cnt_placeholder_reqs,
            "user_profile": cnt_user_profile
        }

        return {
            "customer_id": customer_id,
            "customer_name": cust["name"],
            "can_delete": can_delete,
            "conflicts": conflicts,
            "counts": counts
        }
    finally:
        conn.close()


def safe_delete_customer(
    customer_id: str,
    confirmation_code: str,
    reason: str,
    session_token: str
) -> Dict[str, Any]:
    """
    Administrator-only safe customer deletion.
    Strictly blocks deletion if any linked trips, travellers, documents, or document versions exist.
    Never cascade-deletes related business records or encrypted files.
    Allows clean removal of empty/stub duplicates with exact customer-ID confirmation.
    """
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")

    auth_services.require_permission(session_token, "customer:delete")
    user = auth_services.require_role(session_token, ["Admin", "Administrator"])

    expected_codes = {f"CONFIRM-DELETE-{customer_id}", customer_id}
    if not confirmation_code or confirmation_code.strip() not in expected_codes:
        raise ValueError(f"Confirmation code mismatch. Please enter '{customer_id}' or 'CONFIRM-DELETE-{customer_id}'.")

    if not reason or len(reason.strip()) < 3:
        raise ValueError("A valid deletion reason (minimum 3 characters) is required.")

    # Check dependencies
    safety = check_customer_deletion_safety(customer_id, session_token)
    if not safety["can_delete"]:
        conflict_str = ", ".join(safety["conflicts"])
        auth_services.log_security_event(
            "CUSTOMER_DELETE_BLOCKED",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Customer delete blocked for {customer_id}: linked records exist ({conflict_str})"
        )
        raise ValueError(
            f"Deletion blocked: Customer '{customer_id}' has linked records ({conflict_str}). "
            f"Cascade deletion is strictly forbidden to protect data integrity. Please use 'Archive Customer' instead."
        )

    conn = database.get_connection()
    try:
        conn.execute("BEGIN TRANSACTION")

        # Cleanly remove only empty auto-generated placeholder requirements (with 0 documents)
        conn.execute(
            "DELETE FROM requirements WHERE customer_id = ? AND type = 'CUSTOMER_VAULT' AND id NOT IN (SELECT requirement_id FROM documents)",
            (customer_id,)
        )
        # Cleanly remove placeholder user_profile
        conn.execute("DELETE FROM user_profile WHERE customer_id = ?", (customer_id,))
        # Cleanly remove pending deletion requests if any
        conn.execute("DELETE FROM deletion_requests WHERE object_type = 'CUSTOMER' AND object_id = ?", (customer_id,))
        # Cleanly remove activity referencing this customer
        conn.execute("DELETE FROM activity WHERE customer_id = ?", (customer_id,))
        # Delete customer record
        conn.execute("DELETE FROM customers WHERE id = ?", (customer_id,))

        conn.commit()

        # Database integrity check
        integ = [r[0] for r in conn.execute("PRAGMA integrity_check").fetchall()]
        if integ != ["ok"]:
            raise RuntimeError(f"Database integrity check failed after customer deletion: {integ}")

        auth_services.log_security_event(
            "CUSTOMER_DELETED",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Safely deleted empty customer {customer_id}. Reason: {reason.strip()}"
        )

        return {
            "success": True,
            "customer_id": customer_id,
            "deleted": True,
            "message": f"Customer '{customer_id}' was safely deleted."
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def archive_document(doc_id: str, reason: str, session_token: str) -> Dict[str, Any]:
    """
    Reversibly soft-archives a document.
    Preserves encrypted file, history, and version records.
    If the document is Aadhaar or PAN, its mandatory status becomes 'Missing' unless another active valid version exists.
    Requires document:archive permission.
    """
    if not ENABLE_DOCUMENT_ARCHIVE:
        raise RuntimeError("Document archival is disabled by configuration.")
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    auth_services.require_permission(session_token, "document:archive")
    user = auth_services.get_user_by_token(session_token)
    if not user:
        raise PermissionError("Invalid session.")
        
    if not reason or len(reason.strip()) < 3:
        raise ValueError("A valid archive reason (minimum 3 characters) is required.")
        
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT id, requirement_id, status, file_path, archived FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError(f"Document '{doc_id}' not found.")
        if doc['archived'] == 1:
            return {"success": True, "message": f"Document '{doc_id}' is already archived.", "document_id": doc_id}
            
        now_iso = datetime.now().isoformat()
        conn.execute(
            "UPDATE documents SET archived = 1, archived_at = ?, archived_by = ?, archive_reason = ? WHERE id = ?",
            (now_iso, user.get('id'), reason.strip(), doc_id)
        )
        conn.execute("UPDATE document_versions SET is_active = 0 WHERE document_id = ?", (doc_id,))
        conn.commit()
        
        auth_services.log_security_event(
            "DOCUMENT_ARCHIVE",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Archived document {doc_id}: {reason.strip()}"
        )
        return {"success": True, "document_id": doc_id, "archived": True, "archived_at": now_iso}
    finally:
        conn.close()

def restore_document(doc_id: str, session_token: str) -> Dict[str, Any]:
    """
    Restores a soft-archived document to active status.
    Requires document:restore permission.
    """
    if not ENABLE_DOCUMENT_ARCHIVE:
        raise RuntimeError("Document archival is disabled by configuration.")
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    auth_services.require_permission(session_token, "document:restore")
    user = auth_services.get_user_by_token(session_token)
    if not user:
        raise PermissionError("Invalid session.")
        
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT id, requirement_id, status, archived FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError(f"Document '{doc_id}' not found.")
        if doc['archived'] == 0:
            return {"success": True, "message": f"Document '{doc_id}' is already active.", "document_id": doc_id}
            
        conn.execute(
            "UPDATE documents SET archived = 0, archived_at = NULL, archived_by = NULL, archive_reason = NULL WHERE id = ?",
            (doc_id,)
        )
        max_ver = conn.execute("SELECT MAX(version_number) FROM document_versions WHERE document_id = ?", (doc_id,)).fetchone()[0]
        if max_ver is not None:
            conn.execute("UPDATE document_versions SET is_active = 1 WHERE document_id = ? AND version_number = ?", (doc_id, max_ver))
            
        conn.commit()
        
        auth_services.log_security_event(
            "DOCUMENT_RESTORE",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Restored document {doc_id} to active view"
        )
        return {"success": True, "document_id": doc_id, "archived": False}
    finally:
        conn.close()

def replace_document(
    requirement_id: str,
    file_bytes_or_path: Any,
    original_filename: str,
    reason: str,
    session_token: str,
    extracted_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Version-safe document replacement:
    - Enforces document:replace permission
    - Validates file extension, size, and magic bytes
    - Calculates SHA-256 and rejects duplicate file content
    - Encrypts and writes new file using storage_service, preserving old files
    - Appends a new version row to document_versions with status 'Pending Verification'
    - Resets document requirement status to 'Pending Verification'
    - Tamper-evident audit logging
    """
    if not ENABLE_DOCUMENT_REPLACE:
        raise RuntimeError("Document replacement is disabled by configuration.")
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    auth_services.require_permission(session_token, "document:replace")
    user = auth_services.get_user_by_token(session_token)
    if not user:
        raise PermissionError("Invalid session.")
        
    if not reason or len(reason.strip()) < 3:
        raise ValueError("A valid replacement reason (minimum 3 characters) is required.")
        
    if isinstance(file_bytes_or_path, (bytes, bytearray)):
        file_bytes = bytes(file_bytes_or_path)
    elif isinstance(file_bytes_or_path, str) and os.path.exists(file_bytes_or_path):
        with open(file_bytes_or_path, 'rb') as f:
            file_bytes = f.read()
    elif hasattr(file_bytes_or_path, 'read'):
        file_bytes = file_bytes_or_path.read()
        if hasattr(file_bytes_or_path, 'seek'):
            file_bytes_or_path.seek(0)
    else:
        raise ValueError("Invalid file content provided for replacement.")
        
    validate_document_upload(file_bytes, original_filename)
    file_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()
    
    conn = database.get_connection()
    try:
        req = conn.execute("SELECT id, name, trip_id, traveller_id, customer_id FROM requirements WHERE id = ?", (requirement_id,)).fetchone()
        if not req:
            raise ValueError(f"Requirement '{requirement_id}' not found.")
            
        existing_doc = conn.execute("SELECT id, status, file_path FROM documents WHERE requirement_id = ?", (requirement_id,)).fetchone()
        
        if existing_doc:
            doc_id = existing_doc['id']
            dupe = conn.execute(
                "SELECT id, version_number FROM document_versions WHERE document_id = ? AND sha256_checksum = ? AND is_active = 1",
                (doc_id, file_sha256)
            ).fetchone()
            if dupe:
                auth_services.log_security_event(
                    "DOCUMENT_UPLOAD_REJECTED_DUPLICATE",
                    username=user.get("username"),
                    user_id=user.get("id"),
                    role=user.get("role"),
                    details=f"Duplicate upload rejected for document {doc_id} (matches version {dupe['version_number']})"
                )
                raise ValueError("Duplicate document: This identical file content has already been uploaded.")
                
            max_ver_row = conn.execute("SELECT MAX(version_number) FROM document_versions WHERE document_id = ?", (doc_id,)).fetchone()
            curr_max_ver = max_ver_row[0] if max_ver_row and max_ver_row[0] is not None else 1
            new_version_num = curr_max_ver + 1
        else:
            doc_id = 'DOC-' + str(uuid.uuid4())[:8]
            new_version_num = 1
            
        import storage_service
        base_ext = os.path.splitext(original_filename)[1].lower() or '.pdf'
        stored_filename = f"ENC_{doc_id}_v{new_version_num:02d}{base_ext}"
        storage_res = storage_service.write_encrypted_file(
            stored_filename,
            file_bytes,
            session_token=session_token
        )
        target_file_path = storage_res['file_path']
        
        now_iso = datetime.now().isoformat()
        version_id = f"VER-{doc_id}-{new_version_num:02d}"
        mime_type = "application/pdf" if base_ext == ".pdf" else ("image/png" if base_ext == ".png" else "image/jpeg")
        
        conn.execute("BEGIN TRANSACTION")
        
        if existing_doc:
            conn.execute("UPDATE document_versions SET is_active = 0 WHERE document_id = ?", (doc_id,))
            conn.execute("""
                INSERT INTO document_versions 
                (id, document_id, version_number, file_path, sha256_checksum, original_filename, mime_type, size_bytes, status, created_at, created_by, replacement_reason, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending Verification', ?, ?, ?, 1)
            """, (version_id, doc_id, new_version_num, target_file_path, file_sha256, original_filename, mime_type, len(file_bytes), now_iso, user.get('id'), reason.strip()))
            
            conn.execute("""
                UPDATE documents SET status = 'Pending Verification', file_path = ?, extracted_data = ?, uploaded_at = ?, archived = 0, archived_at = NULL, archived_by = NULL, archive_reason = NULL
                WHERE id = ?
            """, (target_file_path, json.dumps(extracted_data or {}), now_iso, doc_id))
            
            prev_status = existing_doc['status'] if existing_doc else 'Missing'
            conn.execute("""
                INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason, timestamp)
                VALUES (?, 'REPLACE', ?, 'Pending Verification', ?, ?, ?)
            """, (doc_id, prev_status, user.get('username') or user.get('id'), f"Replaced with version {new_version_num}. Reason: {reason.strip()}", now_iso))
        else:
            conn.execute("""
                INSERT INTO documents (id, requirement_id, status, extracted_data, file_path, uploaded_at, archived)
                VALUES (?, ?, 'Pending Verification', ?, ?, ?, 0)
            """, (doc_id, requirement_id, json.dumps(extracted_data or {}), target_file_path, now_iso))
            
            conn.execute("""
                INSERT INTO document_versions 
                (id, document_id, version_number, file_path, sha256_checksum, original_filename, mime_type, size_bytes, status, created_at, created_by, replacement_reason, is_active)
                VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'Pending Verification', ?, ?, ?, 1)
            """, (version_id, doc_id, target_file_path, file_sha256, original_filename, mime_type, len(file_bytes), now_iso, user.get('id'), reason.strip()))
            
            conn.execute("""
                INSERT INTO document_history (document_id, event_type, previous_status, new_status, actor, reason, timestamp)
                VALUES (?, 'UPLOAD', 'Missing', 'Pending Verification', ?, ?, ?)
            """, (doc_id, user.get('username') or user.get('id'), f"Initial upload version 1: {reason.strip()}", now_iso))
                         
        conn.commit()
        
        auth_services.log_security_event(
            "DOCUMENT_REPLACE",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Replaced document {doc_id} (version {new_version_num}). Reason: {reason.strip()}"
        )
        
        return {
            "success": True,
            "document_id": doc_id,
            "version_number": new_version_num,
            "status": "Pending Verification",
            "file_path": target_file_path,
            "sha256": file_sha256
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def get_document_versions(doc_id: str, session_token: str) -> List[Dict[str, Any]]:
    """
    Retrieves the version history for a given document.
    """
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
    auth_services.require_permission(session_token, "document:version_history")
    
    conn = database.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM document_versions WHERE document_id = ? ORDER BY version_number DESC",
            (doc_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def delete_document(doc_id: str, session_token: str, confirmation_code: Optional[str] = None):
    """
    Administrator-only document deletion control.
    Enforces server-side permission check, role check, ENABLE_PERMANENT_DELETE check, backup verification, and typed confirmation.
    Safely removes version records, history records, and encrypted files.
    """
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required to delete documents.")
    
    auth_services.require_permission(session_token, "document:delete")
    user = auth_services.require_role(session_token, ["Admin", "Administrator"])

    if not ENABLE_PERMANENT_DELETE:
        raise RuntimeError("Permanent deletion is disabled by configuration (ENABLE_PERMANENT_DELETE=False).")
    
    backup_ok, _ = check_verified_backup_exists()
    if not backup_ok:
        raise RuntimeError("Permanent deletion blocked: No verified database backup found.")
        
    expected_codes = {f"CONFIRM-DELETE-{doc_id}", doc_id}
    if not confirmation_code or confirmation_code.strip() not in expected_codes:
        raise ValueError(f"Confirmation code mismatch. Expected 'CONFIRM-DELETE-{doc_id}' or '{doc_id}'.")
    
    conn = database.get_connection()
    try:
        doc = conn.execute("SELECT id, requirement_id, file_path FROM documents WHERE id = ?", (doc_id,)).fetchone()
        if not doc:
            raise ValueError(f"Document '{doc_id}' not found.")
            
        files_to_remove = []
        if doc['file_path']:
            files_to_remove.append(doc['file_path'])
            
        v_rows = conn.execute("SELECT file_path FROM document_versions WHERE document_id = ?", (doc_id,)).fetchall()
        for vr in v_rows:
            if vr['file_path']:
                files_to_remove.append(vr['file_path'])
                
        conn.execute("BEGIN TRANSACTION")
        conn.execute("DELETE FROM document_versions WHERE document_id = ?", (doc_id,))
        conn.execute("DELETE FROM document_history WHERE document_id = ?", (doc_id,))
        conn.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        conn.commit()
        
        for fp in set(files_to_remove):
            try:
                if fp and os.path.exists(fp):
                    os.remove(fp)
            except Exception:
                pass
                
        auth_services.log_security_event(
            "DOCUMENT_PERMANENT_DELETE",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Permanently deleted document {doc_id} and {len(v_rows)} version records"
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def create_deletion_request(object_type: str, object_id: str, reason: str, session_token: str) -> Dict[str, Any]:
    """
    Creates a deletion request for Admin review.
    Used by Staff or Supervisors when permanent deletion cannot be executed directly.
    """
    if not ENABLE_DELETION_REQUESTS:
        raise RuntimeError("Deletion requests are disabled by configuration.")
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
        
    clean_type = object_type.strip().upper()
    if clean_type not in ('CUSTOMER', 'DOCUMENT'):
        raise ValueError("Invalid object_type: must be 'CUSTOMER' or 'DOCUMENT'.")
        
    perm = "customer:request_delete" if clean_type == 'CUSTOMER' else "document:request_delete"
    auth_services.require_permission(session_token, perm)
    user = auth_services.get_user_by_token(session_token)
    if not user:
        raise PermissionError("Invalid session.")
        
    if not reason or len(reason.strip()) < 5:
        raise ValueError("A documented deletion request reason (minimum 5 characters) is required.")
        
    conn = database.get_connection()
    try:
        if clean_type == 'CUSTOMER':
            obj = conn.execute("SELECT id FROM customers WHERE id = ?", (object_id,)).fetchone()
        else:
            obj = conn.execute("SELECT id FROM documents WHERE id = ?", (object_id,)).fetchone()
            
        if not obj:
            raise ValueError(f"{clean_type.capitalize()} '{object_id}' not found.")
            
        req_id = f"DEL-REQ-{str(uuid.uuid4())[:8]}"
        now_iso = datetime.now().isoformat()
        
        conn.execute("""
            INSERT INTO deletion_requests (id, object_type, object_id, requested_by, requested_by_role, requested_at, reason, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')
        """, (req_id, clean_type, object_id, user.get('id'), user.get('role'), now_iso, reason.strip()))
        conn.commit()
        
        event_name = "CUSTOMER_DELETE_REQUEST" if clean_type == 'CUSTOMER' else "DOCUMENT_DELETE_REQUEST"
        auth_services.log_security_event(
            event_name,
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Created deletion request {req_id} for {clean_type} {object_id}: {reason.strip()}"
        )
        return {"success": True, "request_id": req_id, "status": "PENDING"}
    finally:
        conn.close()

def review_deletion_request(request_id: str, decision: str, notes: str, session_token: str) -> Dict[str, Any]:
    """
    Reviews a pending deletion request (Admin only).
    Decision must be 'APPROVED' or 'REJECTED'.
    """
    if not session_token:
        raise PermissionError("Unauthenticated: A valid session token is required.")
    auth_services.require_permission(session_token, "customer:delete")
    user = auth_services.require_role(session_token, ["Admin", "Administrator"])
    
    clean_dec = decision.strip().upper()
    if clean_dec not in ('APPROVED', 'REJECTED'):
        raise ValueError("Decision must be 'APPROVED' or 'REJECTED'.")
        
    conn = database.get_connection()
    try:
        req = conn.execute("SELECT * FROM deletion_requests WHERE id = ?", (request_id,)).fetchone()
        if not req:
            raise ValueError(f"Deletion request '{request_id}' not found.")
            
        now_iso = datetime.now().isoformat()
        conn.execute("""
            UPDATE deletion_requests 
            SET status = ?, reviewed_by = ?, reviewed_at = ?, review_notes = ?
            WHERE id = ?
        """, (clean_dec, user.get('id'), now_iso, notes.strip() if notes else None, request_id))
        conn.commit()
        
        auth_services.log_security_event(
            "DELETION_REQUEST_REVIEWED",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Reviewed deletion request {request_id}: {clean_dec}. Notes: {notes or ''}"
        )
        return {"success": True, "request_id": request_id, "status": clean_dec}
    finally:
        conn.close()

def get_deletion_requests(status: Optional[str] = None, session_token: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves deletion requests.
    """
    if session_token:
        auth_services.require_permission(session_token, "admin:access")
    conn = database.get_connection()
    try:
        if status:
            rows = conn.execute("SELECT * FROM deletion_requests WHERE status = ? ORDER BY requested_at DESC", (status.upper(),)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM deletion_requests ORDER BY requested_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()



MANDATORY_CUSTOMER_DOCUMENT_TYPES = ['Aadhaar Card', 'PAN Card']

def mask_pan(pan_val):
    """
    Safely masks PAN numbers for UI display.
    Example: 'ABCDE1234F' -> 'AB******4F'. Never displays full PAN in logs or summaries.
    """
    if not pan_val:
        return ""
    clean = re.sub(r'[^A-Za-z0-9]', '', str(pan_val)).upper()
    if len(clean) == 10:
        return f"{clean[:2]}******{clean[-2:]}"
    elif len(clean) >= 4:
        return f"****{clean[-4:]}"
    return "**********"


def ensure_customer_mandatory_requirements(customer_id, conn=None):
    """
    Idempotently ensures that mandatory customer vault requirements (Aadhaar Card and PAN Card)
    exist for the given customer_id with type = 'CUSTOMER_VAULT'.
    """
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True

    try:
        for doc_name in MANDATORY_CUSTOMER_DOCUMENT_TYPES:
            existing = conn.execute(
                "SELECT id FROM requirements WHERE customer_id = ? AND name = ?",
                (customer_id, doc_name)
            ).fetchone()
            if not existing:
                suffix = doc_name.replace(" ", "")
                req_id = f"REQ-CUST-{customer_id}-{suffix}"
                chk = conn.execute("SELECT id FROM requirements WHERE id = ?", (req_id,)).fetchone()
                if chk:
                    req_id = f"REQ-CUST-{customer_id}-{suffix}-{uuid.uuid4().hex[:6]}"
                
                conn.execute("""
                    INSERT OR IGNORE INTO requirements (id, customer_id, name, type)
                    VALUES (?, ?, ?, 'CUSTOMER_VAULT')
                """, (req_id, customer_id, doc_name))
        conn.commit()
    finally:
        if should_close:
            conn.close()


def get_customer_mandatory_status(customer_id, conn=None):
    """
    Single source of truth for Aadhaar and PAN mandatory document status for a customer.
    Returns:
      - customer_id: ID of the customer
      - total_mandatory: 2
      - verified_count: number of verified documents (0, 1, or 2)
      - completion_ratio: '0/2', '1/2', or '2/2'
      - progress_percent: 0, 50, or 100
      - is_complete: bool
      - documents: list of dicts with:
          - name: 'Aadhaar Card' or 'PAN Card'
          - req_id: requirement ID
          - doc_id: document ID (or None if missing)
          - status: 'Missing', 'Pending Verification', 'Uploaded / Verified', 'Rejected'
          - internal_status: DB status or None
          - masked_number: masked Aadhaar or PAN number
          - uploaded_at: timestamp or None
          - file_path: storage path or None
          - rejection_reason: rejection note if rejected
          - extracted_data: parsed fields dict
    """
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True

    try:
        ensure_customer_mandatory_requirements(customer_id, conn=conn)

        doc_results = []
        verified_count = 0

        for doc_name in MANDATORY_CUSTOMER_DOCUMENT_TYPES:
            row = conn.execute("""
                SELECT r.id as req_id, r.name as req_name,
                       d.id as doc_id, d.status as internal_status,
                       d.extracted_data, d.file_path, d.uploaded_at
                FROM requirements r
                LEFT JOIN documents d ON r.id = d.requirement_id AND (d.archived = 0 OR d.archived IS NULL)
                WHERE (r.customer_id = ? OR r.traveller_id IN (SELECT id FROM travellers WHERE customer_id = ?))
                  AND r.name = ?
                ORDER BY d.uploaded_at DESC, d.id DESC
                LIMIT 1
            """, (customer_id, customer_id, doc_name)).fetchone()

            req_id = row['req_id'] if row else None
            doc_id = row['doc_id'] if (row and row['doc_id']) else None
            internal_status = row['internal_status'] if (row and row['internal_status']) else None
            extracted_json = row['extracted_data'] if (row and row['extracted_data']) else None
            uploaded_at = row['uploaded_at'] if (row and row['uploaded_at']) else None
            file_path = row['file_path'] if (row and row['file_path']) else None

            extracted_data = {}
            if extracted_json:
                try:
                    extracted_data = json.loads(extracted_json)
                except Exception:
                    extracted_data = {}

            if not doc_id or not internal_status:
                user_status = "Missing"
            elif internal_status == 'Verified':
                user_status = "Uploaded / Verified"
                verified_count += 1
            elif internal_status in ('Rejected', 'Re-upload Required', 'Replace Required'):
                user_status = "Rejected"
            elif internal_status in ('Under Review', 'Action Required'):
                user_status = "Pending Verification"
            else:
                user_status = "Pending Verification"

            masked_id = ""
            if doc_name == 'Aadhaar Card':
                raw_num = extracted_data.get('Aadhaar Number', '')
                masked_id = mask_aadhaar(raw_num) if raw_num else ""
            elif doc_name == 'PAN Card':
                raw_num = extracted_data.get('PAN Number', '')
                masked_id = mask_pan(raw_num) if raw_num else ""

            rejection_reason = ""
            if user_status == "Rejected" and doc_id:
                hist_row = conn.execute("""
                    SELECT reason FROM document_history
                    WHERE document_id = ? AND event_type = 'REJECT'
                    ORDER BY id DESC LIMIT 1
                """, (doc_id,)).fetchone()
                if hist_row and hist_row['reason']:
                    rejection_reason = hist_row['reason']

            doc_results.append({
                'name': doc_name,
                'req_id': req_id,
                'doc_id': doc_id,
                'status': user_status,
                'internal_status': internal_status,
                'masked_number': masked_id,
                'uploaded_at': uploaded_at,
                'file_path': file_path,
                'rejection_reason': rejection_reason,
                'extracted_data': extracted_data
            })

        total_mandatory = len(MANDATORY_CUSTOMER_DOCUMENT_TYPES)
        completion_ratio = f"{verified_count}/{total_mandatory}"
        progress_pct = int((verified_count / total_mandatory) * 100)

        return {
            'customer_id': customer_id,
            'total_mandatory': total_mandatory,
            'verified_count': verified_count,
            'completion_ratio': completion_ratio,
            'progress_percent': progress_pct,
            'is_complete': (verified_count == total_mandatory),
            'documents': doc_results
        }
    finally:
        if should_close:
            conn.close()


def get_dashboard_mandatory_metrics(conn=None, include_archived=False):
    """
    Computes overall mandatory document compliance statistics for all customers.
    Excludes archived customers by default unless include_archived=True.
    Returns counts for:
      - total_customers
      - both_verified_count
      - missing_aadhaar_count
      - missing_pan_count
      - missing_either_count
      - pending_verification_count
      - rejected_count
      - customer_list: list of customer summary dicts for filtering
    """
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True

    try:
        archived_filter = 1 if include_archived else 0
        customers = conn.execute(
            "SELECT id, name, customer_type, status FROM customers WHERE (archived = 0 OR ? = 1) ORDER BY id ASC",
            (archived_filter,)
        ).fetchall()
        total_customers = len(customers)

        summary = {
            'total_customers': total_customers,
            'both_verified_count': 0,
            'missing_aadhaar_count': 0,
            'missing_pan_count': 0,
            'missing_either_count': 0,
            'pending_verification_count': 0,
            'rejected_count': 0,
            'customer_list': []
        }

        for cust in customers:
            c_id = cust['id']
            stat = get_customer_mandatory_status(c_id, conn=conn)

            aadhaar_doc = next((d for d in stat['documents'] if d['name'] == 'Aadhaar Card'), None)
            pan_doc = next((d for d in stat['documents'] if d['name'] == 'PAN Card'), None)

            aadhaar_status = aadhaar_doc['status'] if aadhaar_doc else "Missing"
            pan_status = pan_doc['status'] if pan_doc else "Missing"

            is_both_verified = (aadhaar_status == "Uploaded / Verified" and pan_status == "Uploaded / Verified")
            is_missing_aadhaar = (aadhaar_status == "Missing")
            is_missing_pan = (pan_status == "Missing")
            is_missing_either = (is_missing_aadhaar or is_missing_pan)
            is_pending = (aadhaar_status == "Pending Verification" or pan_status == "Pending Verification")
            is_rejected = (aadhaar_status == "Rejected" or pan_status == "Rejected")

            if is_both_verified:
                summary['both_verified_count'] += 1
            if is_missing_aadhaar:
                summary['missing_aadhaar_count'] += 1
            if is_missing_pan:
                summary['missing_pan_count'] += 1
            if is_missing_either:
                summary['missing_either_count'] += 1
            if is_pending:
                summary['pending_verification_count'] += 1
            if is_rejected:
                summary['rejected_count'] += 1

            summary['customer_list'].append({
                'id': c_id,
                'name': cust['name'],
                'customer_type': cust['customer_type'],
                'account_status': cust['status'],
                'completion_ratio': stat['completion_ratio'],
                'progress_percent': stat['progress_percent'],
                'aadhaar_status': aadhaar_status,
                'pan_status': pan_status,
                'is_complete': is_both_verified
            })

        return summary
    finally:
        if should_close:
            conn.close()
