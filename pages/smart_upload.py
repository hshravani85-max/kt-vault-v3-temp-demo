import streamlit as st
import time
from ui_helpers import inject_custom_css, render_top_nav
from document_processor import process_document, validate_traveller_identity
import services
from services import save_document
import auth_services
import os
import re
import database
import uuid

inject_custom_css()
render_top_nav()

def reset_upload_workflow_state():
    st.session_state['upload_step'] = 1
    for key in ['uploaded_filename', 'upload_safe_path', 'extracted_result', 'smart_upload_confirmed_type', 'smart_upload_passport_kind', 'smart_upload_file_sha256']:
        st.session_state.pop(key, None)
    st.session_state['upload_version'] = st.session_state.get('upload_version', 0) + 1
    st.session_state['upload_instance_id'] = uuid.uuid4().hex[:8]
    for k in list(st.session_state.keys()):
        if str(k).startswith("smart_up_") or str(k).startswith("file_uploader_") or str(k).startswith("confirm_doc_type_select") or str(k).startswith("mismatch_"):
            st.session_state.pop(k, None)

req_id = st.session_state.get('upload_req_id')
conn = database.get_connection()

if not req_id:
    if st.session_state.get('active_upload_req_id') is not None:
        reset_upload_workflow_state()
        st.session_state.pop('active_upload_req_id', None)
        st.session_state.pop('active_upload_trip_id', None)
        st.session_state.pop('active_upload_customer_id', None)
        
    st.info("No requirement pre-selected.")
    st.write("### Select a Requirement")
    trip_id = st.session_state.get('upload_trip_id')
    if trip_id:
        pending_reqs = conn.execute("SELECT r.id, r.name, c.name as c_name, t.name as t_name FROM requirements r JOIN trips t ON r.trip_id=t.id JOIN customers c ON t.customer_id=c.id WHERE r.trip_id=?", (trip_id,)).fetchall()
    else:
        pending_reqs = conn.execute("SELECT r.id, r.name, c.name as c_name, t.name as t_name FROM requirements r JOIN trips t ON r.trip_id=t.id JOIN customers c ON t.customer_id=c.id").fetchall()
    
    if not pending_reqs:
        st.warning("No requirements available.")
        conn.close()
        st.stop()
        
    req_options = {r['id']: f"{r['c_name']} - {r['t_name']} - {r['name']}" for r in pending_reqs}
    selected_req = st.selectbox("Choose Requirement to Upload:", options=list(req_options.keys()), format_func=lambda x: req_options[x])
    
    if st.button("Proceed to Upload", type="primary"):
        reset_upload_workflow_state()
        st.session_state['upload_req_id'] = selected_req
        conn.close()
        st.rerun()
    conn.close()
    st.stop()

req = conn.execute('''
    SELECT r.*,
           t.customer_id AS trip_customer_id,
           tr.customer_id AS traveller_customer_id,
           COALESCE(t.customer_id, tr.customer_id) AS customer_id,
           COALESCE(c.name, c2.name) AS c_name,
           t.name AS t_name,
           tr.name AS traveller_name
    FROM requirements r
    LEFT JOIN trips t ON r.trip_id = t.id
    LEFT JOIN customers c ON t.customer_id = c.id
    LEFT JOIN travellers tr ON r.traveller_id = tr.id
    LEFT JOIN customers c2 ON tr.customer_id = c2.id
    WHERE r.id = ?
''', (req_id,)).fetchone()

trip_traveller_names = []
if req and req['trip_id']:
    tt_rows = conn.execute("SELECT tr.name FROM trip_travellers tt JOIN travellers tr ON tt.traveller_id = tr.id WHERE tt.trip_id = ?", (req['trip_id'],)).fetchall()
    trip_traveller_names = [r['name'] for r in tt_rows if r['name']]
conn.close()

if not req:
    st.error(f"Requirement '{req_id}' not found.")
    reset_upload_workflow_state()
    st.session_state.pop('upload_req_id', None)
    st.session_state.pop('active_upload_req_id', None)
    st.session_state.pop('active_upload_trip_id', None)
    st.session_state.pop('active_upload_customer_id', None)
    st.stop()

curr_context = (req_id, req['trip_id'], req['customer_id'])
active_context = (
    st.session_state.get('active_upload_req_id'),
    st.session_state.get('active_upload_trip_id'),
    st.session_state.get('active_upload_customer_id')
)

if curr_context != active_context:
    reset_upload_workflow_state()
    st.session_state['active_upload_req_id'] = req_id
    st.session_state['active_upload_trip_id'] = req['trip_id']
    st.session_state['active_upload_customer_id'] = req['customer_id']

if 'upload_instance_id' not in st.session_state:
    st.session_state['upload_instance_id'] = uuid.uuid4().hex[:8]

if st.button("← Back to Trip"):
    target_trip_id = req['trip_id']
    reset_upload_workflow_state()
    st.session_state.pop('upload_req_id', None)
    st.session_state.pop('upload_trip_id', None)
    st.session_state.pop('active_upload_req_id', None)
    st.session_state.pop('active_upload_trip_id', None)
    st.session_state.pop('active_upload_customer_id', None)
    st.query_params.trip_id = target_trip_id
    st.session_state['nav_page'] = "trip_workspace"
    st.query_params.page = "trip_workspace"
    st.rerun()

st.markdown('<h1 style="color:#0B2348; margin:0; font-size:2rem; font-weight:800;">Smart Upload</h1>', unsafe_allow_html=True)
st.markdown(f'<p style="color:#64748B; margin:4px 0 16px 0; font-size:0.95rem;">Uploading <strong>{req["name"]}</strong> for <strong>{req["c_name"]}</strong> ({req["t_name"]})</p>', unsafe_allow_html=True)

col1, col2 = st.columns([2, 1])

with col2:
    with st.container(border=True):
        st.markdown("#### 📋 Upload Workflow")
        st.markdown(
            "1. Upload document file (PDF / Image)\n"
            "2. System extracts details & verifies format\n"
            "3. Review and confirm fields\n"
            "4. Saved to vault as Under Review"
        )

with col1:
    if 'upload_step' not in st.session_state:
        st.session_state['upload_step'] = 1

    if st.session_state['upload_step'] == 1:
        instance_id = st.session_state.get('upload_instance_id', 'init')
        is_passport_req = 'passport' in (req['name'] or '').lower()
        if is_passport_req:
            passport_choice = st.radio(
                "Passport Origin (Required for AZAPI Endpoint Selection)",
                options=["Indian Passport", "Foreign Passport"],
                key=f"passport_kind_radio_{req_id}_{instance_id}",
                horizontal=True,
            )
            st.session_state['smart_upload_passport_kind'] = "foreign" if "Foreign" in passport_choice else "indian"
        else:
            st.session_state['smart_upload_passport_kind'] = None

        uploader_key = f"file_uploader_{req_id}_{instance_id}"
        uploaded_file = st.file_uploader(
            "Drag & drop document here (PDF, JPG, JPEG, PNG — Max 20MB for AZAPI / 25MB Vault Limit)",
            type=['pdf', 'jpg', 'jpeg', 'png'],
            key=uploader_key
        )

        if uploaded_file is not None:
            raw_bytes = uploaded_file.getvalue()
            if len(raw_bytes) > services.MAX_DOCUMENT_SIZE_BYTES:
                st.error(f"File size exceeds maximum Vault limit of {services.MAX_DOCUMENT_SIZE_BYTES // (1024 * 1024)}MB.")
            else:
                ext = os.path.splitext(uploaded_file.name)[1].lower()
                safe_filename = f"trip_upload_{uuid.uuid4().hex}{ext}"
                import storage_service
                docs_root = storage_service.get_storage_root()
                os.makedirs(docs_root, exist_ok=True)
                target_physical = os.path.join(docs_root, safe_filename)
                db_rel_path = f"documents/{safe_filename}"
                st_token = st.session_state.get('session_token')
                storage_service.write_document_file(
                    target_physical,
                    raw_bytes,
                    session_token=st_token,
                    base_dir=docs_root,
                )

                import hashlib
                st.session_state['uploaded_filename'] = uploaded_file.name
                st.session_state['upload_safe_path'] = db_rel_path
                st.session_state['smart_upload_file_sha256'] = hashlib.sha256(raw_bytes).hexdigest()
                st.session_state.pop('extracted_result', None)
                st.session_state['upload_step'] = 2
                st.rerun()

    elif st.session_state['upload_step'] == 2:
        st.write("Processing document...")
        progress_bar = st.progress(0)
        status_text = st.empty()

        steps = [
            "Reading document...", "✓ Checking file", "✓ Routing extraction",
            "→ Checking AZAPI / Digital Text", "→ Normalizing schema", "→ Preparing review"
        ]

        for i, step in enumerate(steps):
            status_text.text(step)
            progress_bar.progress((i + 1) * 16)
            time.sleep(0.15)

        file_path = st.session_state.get('upload_safe_path')
        p_kind = st.session_state.get('smart_upload_passport_kind')
        import storage_service
        import services
        safe_phys, _ = services.get_safe_document_path(file_path)
        read_target = safe_phys or file_path
        try:
            st_token = st.session_state.get('session_token')
            file_bytes = storage_service.read_decrypted_document(read_target, session_token=st_token, base_dir=storage_service.get_storage_root())
        except Exception:
            file_bytes = b''

        # Duplicate call protection: reuse existing result for identical file bytes + passport_kind
        import hashlib
        f_hash = hashlib.sha256(file_bytes).hexdigest()
        existing_res = st.session_state.get('extracted_result')
        if (
            isinstance(existing_res, dict)
            and existing_res.get('file_sha256') == f_hash
            and existing_res.get('passport_kind') == p_kind
        ):
            result = existing_res
        else:
            result = process_document(
                st.session_state['uploaded_filename'],
                file_bytes,
                expected_requirement=req['name'],
                passport_kind=p_kind,
            )
        st.session_state['extracted_result'] = result
        st.session_state.pop('smart_upload_confirmed_type', None)
        st.session_state['upload_step'] = 3
        st.rerun()

    elif st.session_state['upload_step'] == 3:
        result = st.session_state.get('extracted_result')
        if not result:
            reset_upload_workflow_state()
            st.rerun()
            
        doc_type = result.get('document_type', 'Needs Review')
        type_conf = result.get('type_confidence', 'low')
        instance_id = st.session_state.get('upload_instance_id', 'init')
        
        SUPPORTED_TYPES = [
            'Hotel Voucher',
            'Flight Ticket',
            'Passport',
            'Visa / Entry Document',
            'Travel Insurance',
            'Transfer Voucher',
            'Sightseeing Voucher',
            'Land Voucher',
            'Aadhaar Card',
            'PAN Card',
            'Arrival / Entry Document',
            'Itinerary',
            'Needs Review'
        ]
        
        SCHEMAS = {
            'Passport': ['Full Name', 'Passport Number', 'Date of Birth', 'Nationality', 'Issue Date', 'Expiry Date', 'Place of Issue'],
            'Visa / Entry Document': ['Traveller Name', 'Visa Number / Reference', 'Destination', 'Purpose', 'Travel Dates', 'Issue Date', 'Expiry Date / Valid Until'],
            'Flight Ticket': ['Passenger Name', 'Route', 'Airline', 'Flight Number', 'PNR/Booking Reference', 'Origin', 'Destination', 'Departure Date/Time', 'Arrival Date/Time', 'Cabin Class'],
            'Hotel Voucher': ['Hotel Name', 'Guest Name', 'Check-in Date', 'Check-out Date', 'Booking Confirmation Number', 'Room Type', 'Hotel Address'],
            'Travel Insurance': ['Insured Name', 'Policy Number', 'Insurance Provider', 'Valid From', 'Valid Until', 'Destination / Coverage Area'],
            'Transfer Voucher': ['Passenger Name', 'Booking Reference', 'Pickup Location', 'Dropoff Location', 'Transfer Date', 'Transfer Time'],
            'Sightseeing Voucher': ['Guest Name', 'Booking Reference', 'Tour / Activity Name', 'Activity Date', 'Number of Guests'],
            'Land Voucher': ['Guest / Passenger Name', 'Booking Reference', 'Service / Activity Name', 'Service Date', 'Pickup / Location', 'Dropoff / Destination', 'Service Time', 'Number of Guests'],
            'Aadhaar Card': ['Full Name', 'Aadhaar Number', 'Date of Birth', 'Gender', 'Address'],
            'PAN Card': ['Full Name', 'PAN Number', 'Date of Birth', "Father's Name"],
            'Arrival / Entry Document': ['Traveller Name', 'Trip Name', 'Destination', 'Arrival Date', 'Departure Date', 'Reference Number'],
            'Itinerary': ['Trip Destination', 'Start Date', 'End Date', 'Schedule Summary'],
            'Needs Review': ['Document Details']
        }
        
        # Determine suggestion for uncertain classification based on linked requirement
        req_name_hint = req['name'].lower()
        fallback_suggestion = 'Needs Review'
        for stype in SUPPORTED_TYPES:
            if stype == 'Needs Review': continue
            if stype.lower() in req_name_hint:
                fallback_suggestion = stype
                break
        if fallback_suggestion == 'Needs Review':
            KEYWORD_MAP = {
                'hotel': 'Hotel Voucher',
                'flight': 'Flight Ticket',
                'passport': 'Passport',
                'visa': 'Visa / Entry Document',
                'insurance': 'Travel Insurance',
                'transfer': 'Transfer Voucher',
                'sightseeing': 'Sightseeing Voucher',
                'arrival': 'Arrival / Entry Document',
                'itinerary': 'Itinerary'
            }
            for kw, target_type in KEYWORD_MAP.items():
                if kw in req_name_hint:
                    fallback_suggestion = target_type
                    break

        def remap_extracted_fields(current_fields, target_type):
            schema_fields = SCHEMAS.get(target_type, ['Document Details'])
            FIELD_ALIASES = {
                'Passenger Name': ['Traveller Name', 'Guest Name', 'Insured Name', 'Full Name'],
                'Traveller Name': ['Passenger Name', 'Guest Name', 'Insured Name', 'Full Name'],
                'Guest Name': ['Traveller Name', 'Passenger Name', 'Insured Name', 'Full Name'],
                'Insured Name': ['Traveller Name', 'Passenger Name', 'Guest Name', 'Full Name'],
                'Full Name': ['Traveller Name', 'Passenger Name', 'Guest Name', 'Insured Name'],
                'Booking Reference': ['PNR/Booking Reference', 'Booking Confirmation Number', 'Reference Number', 'Visa Number / Reference', 'Policy Number'],
                'PNR/Booking Reference': ['Booking Reference', 'Booking Confirmation Number', 'Reference Number'],
                'Booking Confirmation Number': ['Booking Reference', 'PNR/Booking Reference', 'Reference Number'],
                'Reference Number': ['Booking Reference', 'PNR/Booking Reference', 'Booking Confirmation Number', 'Visa Number / Reference', 'Policy Number']
            }
            new_fields = {}
            for sf in schema_fields:
                val = current_fields.get(sf, '')
                if not val and sf in FIELD_ALIASES:
                    for alias in FIELD_ALIASES[sf]:
                        if current_fields.get(alias):
                            val = current_fields[alias]
                            break
                new_fields[sf] = val
            if target_type == 'Arrival / Entry Document' and not new_fields.get('Trip Name'):
                trip_title = req['t_name'] if ('t_name' in req.keys() and req['t_name']) else ''
                if trip_title:
                    new_fields['Trip Name'] = trip_title
            return new_fields

        # Check for high-confidence document type mismatch against the requirement
        is_type_mismatch = (
            type_conf == 'high'
            and doc_type != 'Needs Review'
            and fallback_suggestion != 'Needs Review'
            and doc_type != fallback_suggestion
        )

        if is_type_mismatch:
            st.error(
                f"⚠️ **Document Type Mismatch Detected**\n\n"
                f"• **Target Requirement:** {req['name']} (expects **{fallback_suggestion}**)\n\n"
                f"• **Uploaded Document Type:** **{doc_type}** (High Confidence)\n\n"
                f"The uploaded document appears to be a **{doc_type}**, which does not match the requirement **{req['name']}**."
            )
            
            c_reup, c_cancel = st.columns(2)
            with c_reup:
                if st.button("🔄 Re-upload Correct Document", key=f"btn_reupload_{instance_id}", type="primary"):
                    safe_path = st.session_state.get('upload_safe_path')
                    if safe_path and os.path.exists(safe_path):
                        try:
                            os.remove(safe_path)
                        except Exception:
                            pass
                    reset_upload_workflow_state()
                    st.rerun()
            with c_cancel:
                if st.button("← Cancel & Return to Trip", key=f"btn_cancel_mismatch_{instance_id}"):
                    target_trip_id = req['trip_id']
                    reset_upload_workflow_state()
                    st.session_state.pop('upload_req_id', None)
                    st.session_state.pop('upload_trip_id', None)
                    st.session_state.pop('active_upload_req_id', None)
                    st.session_state.pop('active_upload_trip_id', None)
                    st.session_state.pop('active_upload_customer_id', None)
                    st.query_params.trip_id = target_trip_id
                    st.session_state['nav_page'] = "trip_workspace"
                    st.query_params.page = "trip_workspace"
                    st.rerun()

            confirmed_type = st.session_state.get('smart_upload_confirmed_type', doc_type)
            st.session_state['smart_upload_confirmed_type'] = confirmed_type

        elif doc_type != 'Needs Review' and type_conf == 'high':
            st.success(f"{doc_type} Detected ✓")
            confirmed_type = st.session_state.get('smart_upload_confirmed_type', doc_type)
            st.session_state['smart_upload_confirmed_type'] = confirmed_type
        else:
            st.warning("⚠️ Document type could not be confidently identified. Please review and confirm the document type.")
            suggested_type = doc_type if doc_type in SUPPORTED_TYPES and doc_type != 'Needs Review' else fallback_suggestion
            default_idx = SUPPORTED_TYPES.index(suggested_type) if suggested_type in SUPPORTED_TYPES else SUPPORTED_TYPES.index('Needs Review')
            
            confirmed_type = st.session_state.get('smart_upload_confirmed_type', suggested_type)
            sel_idx = SUPPORTED_TYPES.index(confirmed_type) if confirmed_type in SUPPORTED_TYPES else default_idx
            
            selected_type = st.selectbox(
                "Please confirm or select the correct Document Type:",
                options=SUPPORTED_TYPES,
                index=sel_idx,
                key=f"confirm_doc_type_select_{instance_id}"
            )
            
            if selected_type != confirmed_type:
                st.session_state['smart_upload_confirmed_type'] = selected_type
                confirmed_type = selected_type
                st.session_state['extracted_result']['document_type'] = selected_type
                st.session_state['extracted_result']['extracted_fields'] = remap_extracted_fields(result.get('extracted_fields', {}), selected_type)
                for k in list(st.session_state.keys()):
                    if str(k).startswith("smart_up_"):
                        st.session_state.pop(k, None)
                st.rerun()

        st.write("### Review Extracted Information")
        
        if result.get('manual_review_required'):
            st.warning("Manual Review Mode: Please verify fields against the document preview before saving.")

        warnings_list = result.get('warnings', [])
        for w in warnings_list:
            st.warning(w)

        if result.get('can_retry_azapi'):
            if st.button("🔄 Retry AZAPI Extraction", key=f"btn_retry_azapi_{instance_id}", help="Explicit manual retry (zero automatic retries)."):
                import storage_service
                import services as _svc
                safe_phys, _ = _svc.get_safe_document_path(st.session_state.get('upload_safe_path'))
                try:
                    retry_bytes = storage_service.read_decrypted_document(
                        safe_phys or st.session_state.get('upload_safe_path'),
                        session_token=st.session_state.get('session_token'),
                        base_dir=storage_service.get_storage_root(),
                    )
                except Exception:
                    retry_bytes = b''
                retried = process_document(
                    st.session_state['uploaded_filename'],
                    retry_bytes,
                    expected_requirement=req['name'],
                    passport_kind=st.session_state.get('smart_upload_passport_kind'),
                    force_retry=True,
                )
                st.session_state['extracted_result'] = retried
                for k in list(st.session_state.keys()):
                    if str(k).startswith("smart_up_"):
                        st.session_state.pop(k, None)
                st.rerun()

        st.info("Please fill or correct any missing or incorrect fields below before saving. Information requires human confirmation.")
        
        # Ensure schema matches confirmed type
        schema_fields = SCHEMAS.get(confirmed_type, ['Document Details'])
        curr_fields = result.get('extracted_fields', {})
        fields = {sf: curr_fields.get(sf, '') for sf in schema_fields}
        
        # Sourced booking context pre-fill for Arrival / Entry Document
        if confirmed_type == 'Arrival / Entry Document' and not fields.get('Trip Name'):
            trip_title = req['t_name'] if ('t_name' in req.keys() and req['t_name']) else ''
            if trip_title:
                fields['Trip Name'] = trip_title
                curr_fields['Trip Name'] = trip_title
        
        updated_fields = {}
        c1, c2 = st.columns(2)
        idx = 0
        for k, v in fields.items():
            widget_key = f"smart_up_{instance_id}_{confirmed_type}_{k}"
            if idx % 2 == 0:
                with c1: updated_fields[k] = st.text_input(k, value=v, key=widget_key)
            else:
                with c2: updated_fields[k] = st.text_input(k, value=v, key=widget_key)
            idx += 1

        # Validate traveller identity
        expected_traveller = req['traveller_name'] if ('traveller_name' in req.keys() and req['traveller_name']) else None
        customer_name = req['c_name'] if ('c_name' in req.keys() and req['c_name']) else None

        id_validation = validate_traveller_identity(
            doc_type=confirmed_type,
            extracted_fields=updated_fields,
            expected_traveller_name=expected_traveller,
            trip_travellers=trip_traveller_names,
            customer_name=customer_name
        )
        
        is_identity_mismatch = (not id_validation.get('valid', True) and id_validation.get('severity') == 'error')
        
        if id_validation.get('severity') == 'warning':
            st.warning(f"ℹ️ **Traveller Identity Notice:** {id_validation.get('message')}")
        elif is_identity_mismatch:
            st.error(f"🛑 **Traveller Identity Mismatch Detected**\n\n{id_validation.get('message')}")

        # Determine user role
        user_role = st.session_state.get('user_role')
        if not user_role and st.session_state.get('session_token'):
            try:
                cur_user = auth_services.get_user_by_token(st.session_state.get('session_token'))
                if cur_user:
                    user_role = cur_user.get('role')
            except Exception:
                pass
        cur_tok = st.session_state.get('session_token')
        is_supervisor_or_admin = auth_services.has_permission(cur_tok, 'document:verify') if cur_tok else (user_role in ['Supervisor', 'Admin'])

        has_mismatch = is_type_mismatch or is_identity_mismatch
        save_blocked = False
        allow_override = False
        override_reason = ""

        if has_mismatch:
            if not is_supervisor_or_admin:
                st.error(
                    "🔒 **Supervisor or Admin Authorization Required**\n\n"
                    "A document type or traveller identity mismatch was detected. "
                    "Regular staff cannot authorize mismatched documents. "
                    "Please ask a Supervisor or Admin to review and authorize this upload, or re-upload the correct document."
                )
                save_blocked = True
            else:
                st.warning("⚠️ **Authorization Override Available (Supervisor / Admin)**")
                allow_override = st.checkbox(
                    "⚠️ Authorize document type / traveller identity mismatch (Supervisor/Admin Override)",
                    value=st.session_state.get(f"mismatch_override_{instance_id}", False),
                    key=f"mismatch_override_{instance_id}"
                )
                
                if not allow_override:
                    save_blocked = True
                else:
                    override_reason = st.text_input(
                        "Override Reason (mandatory):",
                        value=st.session_state.get(f"mismatch_reason_{instance_id}", ""),
                        key=f"mismatch_reason_{instance_id}",
                        placeholder="Provide explicit operational rationale for authorizing this mismatch..."
                    )
                    if not override_reason or not override_reason.strip():
                        st.warning("⚠️ An explicit override reason is mandatory to save a mismatched document.")
                        save_blocked = True
                    else:
                        save_blocked = False
                        
                    if is_type_mismatch:
                        curr_conf = st.session_state.get('smart_upload_confirmed_type', doc_type)
                        default_idx = SUPPORTED_TYPES.index(curr_conf) if curr_conf in SUPPORTED_TYPES else 0
                        selected_type = st.selectbox(
                            "Override active: Confirm document schema to save under:",
                            options=SUPPORTED_TYPES,
                            index=default_idx,
                            key=f"confirm_doc_type_select_{instance_id}"
                        )
                        if selected_type != curr_conf:
                            st.session_state['smart_upload_confirmed_type'] = selected_type
                            st.session_state['extracted_result']['document_type'] = selected_type
                            st.session_state['extracted_result']['extracted_fields'] = remap_extracted_fields(result.get('extracted_fields', {}), selected_type)
                            for k in list(st.session_state.keys()):
                                if str(k).startswith("smart_up_"):
                                    st.session_state.pop(k, None)
                            st.rerun()
            
        col_c, col_s = st.columns(2)
        if col_c.button("Cancel"):
            target_trip_id = req['trip_id']
            reset_upload_workflow_state()
            st.session_state.pop('upload_req_id', None)
            st.session_state.pop('upload_trip_id', None)
            st.session_state.pop('active_upload_req_id', None)
            st.session_state.pop('active_upload_trip_id', None)
            st.session_state.pop('active_upload_customer_id', None)
            st.query_params.trip_id = target_trip_id
            st.session_state['nav_page'] = "trip_workspace"
            st.query_params.page = "trip_workspace"
            st.rerun()
            
        if save_blocked:
            block_msg = "Blocked: Mismatch detected. Supervisor/Admin authorization with reason required." if has_mismatch else "Blocked: Form incomplete."
            col_s.button("Confirm & Save Document", disabled=True, help=block_msg)
        else:
            if col_s.button("Confirm & Save Document"):
                safe_path = st.session_state.get('upload_safe_path')
                try:
                    save_document(
                        requirement_id=req_id,
                        file_path=safe_path,
                        extracted_data=updated_fields,
                        session_token=st.session_state.get('session_token'),
                        expected_trip_id=req['trip_id'],
                        expected_customer_id=req['customer_id'],
                        override_mismatch=allow_override,
                        override_reason=override_reason.strip() if override_reason else None,
                        preextracted_result=result,
                        passport_kind=st.session_state.get('smart_upload_passport_kind'),
                    )
                except Exception as err:
                    st.error(f"Error saving document: {err}")
                    st.stop()
                    
                # Add activity
                conn = database.get_connection()
                conn.execute("INSERT INTO activity (trip_id, description) VALUES (?, ?)", (req['trip_id'], f"Document {req['name']} uploaded via Smart Upload"))
                conn.commit()
                conn.close()
                
                st.session_state['upload_step'] = 4
                st.rerun()

    elif st.session_state['upload_step'] == 4:
        st.success("Document successfully saved ✓")
        st.info("Workflow status set to Under Review.")
        if st.button("Return to Trip"):
            target_trip_id = req['trip_id']
            reset_upload_workflow_state()
            st.session_state.pop('upload_req_id', None)
            st.session_state.pop('upload_trip_id', None)
            st.session_state.pop('active_upload_req_id', None)
            st.session_state.pop('active_upload_trip_id', None)
            st.session_state.pop('active_upload_customer_id', None)
            st.query_params.trip_id = target_trip_id
            st.session_state['nav_page'] = "trip_workspace"
            st.query_params.page = "trip_workspace"
            st.rerun()
