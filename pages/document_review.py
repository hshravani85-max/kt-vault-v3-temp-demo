import streamlit as st
import textwrap
from ui_helpers import inject_custom_css, render_top_nav, render_badge
import services
if not hasattr(services, 'recover_verified_document_data'):
    import importlib
    try:
        importlib.reload(services)
    except Exception:
        pass

from services import (
    verify_document, reopen_document, reject_document,
    request_reupload_document, save_extracted_information,
    add_document_note, get_safe_document_path, get_document,
    recover_verified_document_data
)
import auth_services
import os
import json
import database

# 1. Page-level authentication gate
session_token = st.session_state.get('session_token')
current_user = None
try:
    current_user = auth_services.require_role(session_token, ['Staff', 'Supervisor', 'Admin'])
except PermissionError:
    st.error("Authentication required: Invalid, missing, or expired session. Please log in.")
    st.stop()

if not current_user:
    st.stop()

user_role = current_user.get('role', 'Staff')
user_full_name = current_user.get('full_name', 'Staff')
is_reviewer = auth_services.has_permission(session_token, 'document:verify')

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

MANDATORY_FIELDS = {
    'Passport': ['Full Name', 'Passport Number', 'Date of Birth', 'Nationality', 'Expiry Date'],
    'Flight Ticket': ['Passenger Name', 'PNR/Booking Reference', 'Route', 'Departure Date/Time', 'Arrival Date/Time'],
    'Visa / Entry Document': ['Traveller Name', 'Visa Number / Reference', 'Destination'],
    'Hotel Voucher': ['Hotel Name', 'Guest Name', 'Check-in Date', 'Check-out Date', 'Booking Confirmation Number'],
    'Travel Insurance': ['Insured Name', 'Policy Number', 'Valid From', 'Valid Until'],
    'Transfer Voucher': ['Passenger Name', 'Booking Reference', 'Pickup Location', 'Dropoff Location', 'Transfer Date'],
    'Sightseeing Voucher': ['Guest Name', 'Booking Reference', 'Tour / Activity Name', 'Activity Date'],
    'Land Voucher': ['Booking Reference', 'Service Date'],
    'Aadhaar Card': ['Full Name', 'Aadhaar Number'],
    'PAN Card': ['Full Name', 'PAN Number'],
    'Arrival / Entry Document': ['Traveller Name', 'Destination', 'Arrival Date', 'Reference Number'],
    'Itinerary': ['Start Date', 'End Date', 'Schedule Summary']
}

def clear_recovery_state(target_id: str):
    """
    Clears all recovery metadata and dynamic text input widget states
    strictly scoped to target_id, preventing stale values from persisting.
    """
    target_pfx = f"rec_edit_{target_id}_"
    keys_to_clear = [
        f'recovery_mode_{target_id}',
        f'rec_data_{target_id}',
        f'rec_type_{target_id}',
        f'rec_conf_{target_id}',
        f'rec_pdf_hash_{target_id}',
        f'rec_data_hash_{target_id}',
        f'rec_reason_input_{target_id}',
        f'rec_confirm_cb_{target_id}'
    ]
    for k in list(st.session_state.keys()):
        if k in keys_to_clear or k.startswith(target_pfx):
            st.session_state.pop(k, None)

def initiate_recovery(doc_dict, target_doc_id):
    import document_processor
    import hashlib
    
    # Flush any previous recovery edits for this document before initializing
    clear_recovery_state(target_doc_id)
    
    raw_path = doc_dict['file_path'] if doc_dict['file_path'] else ""
    safe_full_path, path_err = get_safe_document_path(raw_path)
    if path_err or not os.path.exists(safe_full_path):
        st.error(f"Cannot access document file: {path_err or 'File not found on disk'}")
        return
    import storage_service
    st_token = st.session_state.get('session_token')
    try:
        file_bytes = storage_service.read_decrypted_document(safe_full_path, session_token=st_token)
    except Exception as e:
        st.error(f"Cannot access document: {str(e)}")
        return
    pdf_hash = hashlib.sha256(file_bytes).hexdigest()
    raw_stored = doc_dict['extracted_data'] if doc_dict['extracted_data'] else "{}"
    data_hash = hashlib.sha256(raw_stored.encode('utf-8')).hexdigest()
    
    req_n = doc_dict['req_name'] if ('req_name' in doc_dict.keys() and doc_dict['req_name']) else ''
    res = document_processor.process_document(doc_dict['file_path'], file_bytes, expected_requirement=req_n, session_token=st_token, require_auth=True)
    extracted = res.get('extracted_fields', {})
    if res.get('document_type') == 'Arrival / Entry Document' and not extracted.get('Trip Name'):
        trip_title = doc_dict['trip_name'] if ('trip_name' in doc_dict.keys() and doc_dict['trip_name']) else ''
        if trip_title:
            extracted['Trip Name'] = trip_title
            
    st.session_state[f'rec_pdf_hash_{target_doc_id}'] = pdf_hash
    st.session_state[f'rec_data_hash_{target_doc_id}'] = data_hash
    st.session_state[f'rec_data_{target_doc_id}'] = extracted
    st.session_state[f'rec_type_{target_doc_id}'] = res.get('document_type', req_n)
    st.session_state[f'rec_conf_{target_doc_id}'] = res.get('confidence', {})
    st.session_state[f'recovery_mode_{target_doc_id}'] = True
    st.rerun()

inject_custom_css()
render_top_nav()

doc_id = st.query_params.get("doc_id")
if not doc_id:
    st.markdown('<h1 style="color:#0B2348; margin:0; font-size:2rem; font-weight:800;">Document Review</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:#64748B; margin:4px 0 16px 0; font-size:0.95rem;">Select a travel document below to inspect the original file and verify extracted data.</p>', unsafe_allow_html=True)
    
    docs_needing_review = services.get_all_documents_for_review()
    if docs_needing_review:
        st.markdown('<div class="kt-section-title">📄 Documents Awaiting Review</div>', unsafe_allow_html=True)
        for doc_item in docs_needing_review:
            with st.container():
                c1, c2, c3, c4 = st.columns([3, 3, 2, 2])
                c1.markdown(f"**{doc_item['customer_name']}**<br><span style='font-size:0.82rem; color:#64748B;'>{doc_item['trip_name']}</span>", unsafe_allow_html=True)
                c2.markdown(f"**{doc_item['req_name']}**<br><span style='font-size:0.82rem; color:#64748B;'>Doc ID: <code>{doc_item['id']}</code></span>", unsafe_allow_html=True)
                c3.markdown(render_badge(doc_item['status']), unsafe_allow_html=True)
                if c4.button("Open Review", key=f"sel_rev_{doc_item['id']}", use_container_width=True):
                    st.query_params.doc_id = doc_item['id']
                    st.session_state['nav_page'] = "document_review"
                    st.query_params.page = "document_review"
                    st.rerun()
                st.markdown("<hr style='margin:8px 0; border:none; border-top:1px solid #E5EAF1;'>", unsafe_allow_html=True)
    else:
        st.info("No documents are currently awaiting review. You can select documents from Documents or Customer Vault.")
        if st.button("Browse All Documents", type="primary"):
            st.session_state['nav_page'] = "documents"
            st.query_params.page = "documents"
            st.rerun()
    st.stop()

if st.button("← Back", key="back_btn_doc_review"):
    if 'doc_id' in st.query_params:
        del st.query_params['doc_id']
    st.session_state['nav_page'] = "documents"
    st.query_params.page = "documents"
    st.rerun()

conn = database.get_connection()
d = conn.execute('''
    SELECT d.*, r.name as req_name, r.trip_id, r.traveller_id,
           COALESCE(t.customer_id, tr.customer_id) as customer_id,
           COALESCE(c.name, c2.name) as customer_name, 
           t.name as trip_name
    FROM documents d
    JOIN requirements r ON d.requirement_id = r.id
    LEFT JOIN trips t ON r.trip_id = t.id
    LEFT JOIN customers c ON t.customer_id = c.id
    LEFT JOIN travellers tr ON r.traveller_id = tr.id
    LEFT JOIN customers c2 ON tr.customer_id = c2.id
    WHERE d.id = ?
''', (doc_id,)).fetchone()

veri_act = None
if d:
    veri_act = conn.execute('''
        SELECT * FROM activity 
        WHERE description LIKE ? 
          AND (
              (trip_id IS NOT NULL AND trip_id = ?) 
              OR (customer_id IS NOT NULL AND customer_id = ?)
              OR (trip_id IS NULL AND customer_id IS NULL)
          )
        ORDER BY timestamp DESC LIMIT 1
    ''', (f"%Document {d['id']} verified%", d['trip_id'], d['customer_id'])).fetchone()

conn.close()

if not d:
    st.error("Document not found.")
    st.stop()

st.markdown(textwrap.dedent(f'''
<div style="background:#FFFFFF; border:1px solid #E5EAF1; border-radius:12px; padding:20px 24px; margin-bottom:18px; box-shadow:0 1px 3px rgba(11,35,72,0.04);">
    <div style="font-size:0.75rem; font-weight:700; color:#64748B; text-transform:uppercase; letter-spacing:1px;">DOCUMENT REVIEW & VERIFICATION</div>
    <h2 style="margin:4px 0 0 0; color:#0B2348; font-weight:800; font-size:1.6rem;">{d['req_name']} — {d['customer_name']}</h2>
    <div style="color:#64748B; font-size:0.88rem; margin-top:4px;">Trip: <strong>{d['trip_name']}</strong> &nbsp;|&nbsp; Document ID: <code>{d['id']}</code></div>
</div>
'''), unsafe_allow_html=True)

col1, col2 = st.columns([1, 1])
with col1:
    import base64
    import storage_service
    safe_path, err_msg = get_safe_document_path(d['file_path'])
    if err_msg:
        st.warning(f"Preview unavailable: {err_msg}")
    else:
        st_token = st.session_state.get('session_token')
        try:
            doc_bytes = storage_service.read_decrypted_document(safe_path, session_token=st_token)
            if safe_path.lower().endswith('.pdf'):
                base64_pdf = base64.b64encode(doc_bytes).decode('utf-8')
                pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="600" style="border:1px solid #ccc; border-radius:8px;" type="application/pdf"></iframe>'
                st.markdown(pdf_display, unsafe_allow_html=True)
            elif safe_path.lower().endswith(('.png', '.jpg', '.jpeg')):
                st.image(doc_bytes, use_column_width=True)
            else:
                st.info("Preview unavailable for this file.")
        except Exception:
            st.info("Preview unavailable for this file.")

with col2:
    status = d['status']
    
    if status == 'Verified':
        st.success("✓ **Verified**")
        if veri_act:
            verified_on = veri_act['timestamp'][:19].replace('T', ' ')
            actor_name = veri_act['actor'] if 'actor' in veri_act.keys() else 'Staff'
            st.caption(f"Verified by **{actor_name}** on **{verified_on}**")
    elif status == 'Rejected':
        st.error("✕ **Rejected**")
    elif status == 'Re-upload Required':
        st.warning("⚠️ **Re-upload Required**")
    else:
        st.markdown(f"**Status:** {render_badge(status)}", unsafe_allow_html=True)



    st.write("### Verification History")
    conn = database.get_connection()
    hist = conn.execute("SELECT * FROM document_history WHERE document_id = ? ORDER BY timestamp DESC", (d['id'],)).fetchall()
    
    # Check if dedicated recovery audit records exist
    has_audit_tbl = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='document_recovery_audit'").fetchone()
    rec_audits = []
    if has_audit_tbl:
        rec_audits = conn.execute("SELECT * FROM document_recovery_audit WHERE document_id = ? ORDER BY timestamp DESC", (d['id'],)).fetchall()
    conn.close()

    earliest_hist_ts = min([str(h['timestamp']) for h in hist]) if hist else None
    show_legacy_record = False
    if veri_act:
        v_ts = str(veri_act['timestamp'])
        if not hist:
            show_legacy_record = True
        elif earliest_hist_ts and v_ts[:10] < earliest_hist_ts[:10]:
            show_legacy_record = True

    has_rendered_any_history = False
    if hist:
        has_rendered_any_history = True
        for h in hist:
            st.markdown(f"<small>**{h['timestamp'][:19]}** - {h['event_type']} - Actor: {h['actor']} - Reason: {h['reason']}</small>", unsafe_allow_html=True)

    if rec_audits:
        has_rendered_any_history = True
        for a in rec_audits:
            st.markdown(f"<small style='color:#1a73e8;'>**{a['timestamp'][:19]}** - RECOVERY AUDIT - Actor: {a['actor']} - Reason: {a['reason']} (Tx: {a['transaction_id']})</small>", unsafe_allow_html=True)

    if show_legacy_record:
        has_rendered_any_history = True
        verified_ts = veri_act['timestamp'][:19].replace('T', ' ')
        actor_line = ""
        if 'actor' in veri_act.keys() and veri_act['actor']:
            actor_line = f"<br><small>Actor: {veri_act['actor']}</small>"
        st.markdown(textwrap.dedent(f'''
<div style="background:#f8f9fa; padding:12px; border-radius:6px; border:1px solid #e0e0e0; margin-top:6px; margin-bottom:10px;">
    <strong>Legacy Verification Record</strong><br>
    <small>Verified on: {verified_ts}</small>{actor_line}<br>
    <small>Source: Historical Activity Log</small><br>
    <small style="color:#666;"><em>This verification predates the current document history system.</em></small>
</div>
'''), unsafe_allow_html=True)

    if not has_rendered_any_history:
        st.write("<small>No verification history available.</small>", unsafe_allow_html=True)

    # Document Version History
    st.write("### Document Version History")
    try:
        doc_versions = services.get_document_versions(d['id'], session_token)
        if doc_versions:
            for v in doc_versions:
                v_active = " [ACTIVE]" if v.get('is_active') == 1 else ""
                v_sha = v.get('sha256_checksum', '')[:12] + '...' if v.get('sha256_checksum') else 'N/A'
                v_reason = v.get('replacement_reason') or 'Initial upload'
                st.markdown(
                    f"<div style='background:#F8FAFC; border:1px solid #E2E8F0; border-radius:6px; padding:8px 12px; margin-bottom:6px; font-size:0.83rem;'>"
                    f"<strong>Version {v['version_number']}</strong>{v_active} &bull; Status: <code>{v['status']}</code> &bull; SHA-256: <code>{v_sha}</code><br>"
                    f"<span style='color:#64748B;'>Uploaded: {v['created_at'][:19]} | Reason: {v_reason}</span>"
                    f"</div>",
                    unsafe_allow_html=True
                )
        else:
            st.write("<small>No version records available.</small>", unsafe_allow_html=True)
    except Exception as ex:
        st.caption(f"Version history not accessible: {ex}")

    if status == 'Verified':
        if is_reviewer:
            if st.session_state.get(f'reopen_mode_{doc_id}'):
                st.warning("You are requesting to reopen a VERIFIED document. This will invalidate its current verification and recalculate trip readiness.")
                reason = st.text_input("Mandatory Correction Reason (Required)", key=f"reopen_reason_input_{doc_id}")
                cr1, cr2 = st.columns(2)
                if cr1.button("Cancel", key=f"cancel_reopen_{doc_id}"):
                    st.session_state[f'reopen_mode_{doc_id}'] = False
                    st.rerun()
                if cr2.button("Confirm Reopen", key=f"confirm_reopen_{doc_id}"):
                    if not reason.strip():
                        st.error("Correction reason is required.")
                    else:
                        try:
                            reopen_document(doc_id, reason, session_token)
                            st.session_state[f'reopen_mode_{doc_id}'] = False
                            st.success("Document reopened successfully.")
                            st.rerun()
                        except PermissionError as e:
                            st.error(str(e))
                        except Exception as e:
                            st.error(f"Error reopening: {str(e)}")
            else:
                if st.button("Reopen for Review", key=f"reopen_btn_{doc_id}"):
                    st.session_state[f'reopen_mode_{doc_id}'] = True
                    st.rerun()

    st.write("### Extracted Information")
    
    if st.session_state.get(f'recovery_mode_{doc_id}'):
        if not is_reviewer:
            st.error("Supervised legacy data recovery requires Authorized Reviewer privileges.")
            st.session_state[f'recovery_mode_{doc_id}'] = False
        else:
            st.markdown(textwrap.dedent('''
            <div style="background:#e8f0fe; padding:15px; border-radius:8px; border:1px solid #aecbfa; margin-bottom: 20px;">
                <h4 style="color:#1a73e8; margin-top:0;">🛠️ Supervised Legacy Document Recovery</h4>
                <p style="margin:0; color:#333; font-size:0.95rem;">
                    You are performing a supervised recovery of extracted data for this <strong>Verified</strong> document.
                    The source PDF, verification status, and trip readiness remain intact.
                    All updates will be recorded in the recovery audit table.
                </p>
            </div>
            '''), unsafe_allow_html=True)

            conn_check = database.get_connection()
            has_audit_tbl = bool(conn_check.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='document_recovery_audit'"
            ).fetchone())
            conn_check.close()

            if not has_audit_tbl:
                st.warning("⚠️ Schema Migration Pending: The 'document_recovery_audit' table is not deployed in this database. Migration must be executed before recovery can proceed.")

            req_name = d['req_name'] if ('req_name' in d.keys() and d['req_name']) else ''
            target_schema = SCHEMAS.get(req_name, SCHEMAS.get(st.session_state.get(f'rec_type_{doc_id}'), ['Document Details']))
            req_mandatory = MANDATORY_FIELDS.get(req_name, [])

            col_curr, col_rec = st.columns(2)
            with col_curr:
                st.markdown("##### 📄 Current Stored Data (Read-Only)")
                stored_dict = json.loads(d['extracted_data']) if d['extracted_data'] and d['extracted_data'] != "{}" else {}
                if not stored_dict:
                    st.info("No structured data currently stored (empty `{}`).")
                else:
                    for k, v in stored_dict.items():
                        st.text_input(k, value=str(v), key=f"stored_rec_view_{doc_id}_{k}", disabled=True)

            with col_rec:
                st.markdown("##### ✏️ Proposed Recovered Data (Editable)")
                detected_rec_type = st.session_state.get(f'rec_type_{doc_id}', req_name)
                st.markdown(f"**Detected Type:** `{detected_rec_type}`")

                draft_fields = st.session_state.get(f'rec_data_{doc_id}', {})
                conf_fields = st.session_state.get(f'rec_conf_{doc_id}', {})

                recovered_input_data = {}
                for fld in target_schema:
                    init_val = draft_fields.get(fld, '')
                    is_mand = fld in req_mandatory
                    lbl = f"{fld} *" if is_mand else fld
                    if conf_fields.get(fld) == 'low':
                        lbl += " (Low Confidence / Ambiguous)"
                    val = st.text_input(lbl, value=str(init_val) if init_val is not None else "", key=f"rec_edit_{doc_id}_{fld}")
                    recovered_input_data[fld] = val

                extra_keys = [k for k, v in draft_fields.items() if k not in target_schema and v and str(v).strip()]
                for fld in extra_keys:
                    val = st.text_input(f"{fld} (Additional)", value=str(draft_fields[fld]), key=f"rec_edit_{doc_id}_{fld}")
                    recovered_input_data[fld] = val

            missing_mand = [m for m in req_mandatory if not recovered_input_data.get(m, '').strip()]
            if missing_mand:
                st.markdown(f"<div style='margin-top:10px; margin-bottom:10px;'><small style='color:#c5221f;'><strong>⚠️ Missing Mandatory Fields ({len(missing_mand)}):</strong> {', '.join(missing_mand)}</small></div>", unsafe_allow_html=True)

            st.markdown("---")
            rec_reason = st.text_input("Mandatory Recovery Reason (Required for audit)", key=f"rec_reason_input_{doc_id}", placeholder="e.g. Sourced passenger and flight details from verified booking PDF")
            reverify_confirmed = st.checkbox("I have reviewed the source document and confirm the recovered information is accurate.", key=f"rec_confirm_cb_{doc_id}")

            b1, b2 = st.columns(2)
            if b1.button("Cancel Recovery", key=f"cancel_rec_{doc_id}"):
                clear_recovery_state(doc_id)
                st.rerun()

            if not has_audit_tbl:
                b2.button("Confirm Recovery & Re-verify", key=f"confirm_rec_disabled_{doc_id}", disabled=True, help="Database migration required to enable recovery")
            else:
                if b2.button("Confirm Recovery & Re-verify", type="primary", key=f"confirm_rec_{doc_id}"):
                    if not rec_reason.strip():
                        st.error("Mandatory recovery reason is required.")
                    elif not reverify_confirmed:
                        st.error("You must explicitly review and check the confirmation box.")
                    elif missing_mand:
                        st.error(f"Cannot complete recovery: Missing mandatory fields: {', '.join(missing_mand)}")
                    else:
                        try:
                            clean_data = {k: v.strip() for k, v in recovered_input_data.items() if v and str(v).strip()}
                            recover_verified_document_data(
                                doc_id=doc_id,
                                recovered_data=clean_data,
                                reason=rec_reason.strip(),
                                session_token=session_token,
                                expected_pdf_sha256=st.session_state.get(f'rec_pdf_hash_{doc_id}'),
                                expected_data_hash=st.session_state.get(f'rec_data_hash_{doc_id}'),
                                reverify=reverify_confirmed
                            )
                            clear_recovery_state(doc_id)
                            st.success("Document recovered and re-verified successfully! Audit record created.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Recovery failed: {str(e)}")

    elif st.session_state.get(f'reextract_mode_{doc_id}'):
        st.info("Please correct any missing or incorrect fields below before saving. Extracted information requires human confirmation.")
        re_data = st.session_state.get(f'reextract_data_{doc_id}', {})
        req_n = d['req_name'].lower()
        fallback_type = 'Needs Review'
        for stype in ['Passport', 'Visa / Entry Document', 'Flight Ticket', 'Hotel Voucher', 'Travel Insurance', 'Transfer Voucher', 'Sightseeing Voucher', 'Arrival / Entry Document', 'Itinerary']:
            if stype.lower() in req_n:
                fallback_type = stype
                break
        if fallback_type == 'Needs Review':
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
                if kw in req_n:
                    fallback_type = target_type
                    break
        detected_t = st.session_state.get(f'reextract_type_{doc_id}', fallback_type)
        def_idx = SUPPORTED_TYPES.index(detected_t) if detected_t in SUPPORTED_TYPES else 0
        chosen_type = st.selectbox("Confirm Document Type Form:", options=SUPPORTED_TYPES, index=def_idx, key=f"re_type_select_{doc_id}")
        if chosen_type != detected_t:
            st.session_state[f'reextract_type_{doc_id}'] = chosen_type
            target_fields = SCHEMAS.get(chosen_type, ['Document Details'])
            # Clear or safely map fields, discarding stale fields from previous type
            FIELD_ALIASES = {
                'Passenger Name': ['Traveller Name', 'Guest Name', 'Insured Name', 'Full Name'],
                'Traveller Name': ['Passenger Name', 'Guest Name', 'Insured Name', 'Full Name'],
                'Guest Name': ['Traveller Name', 'Passenger Name', 'Insured Name', 'Full Name'],
                'Insured Name': ['Traveller Name', 'Passenger Name', 'Guest Name', 'Full Name'],
                'Full Name': ['Traveller Name', 'Passenger Name', 'Guest Name', 'Insured Name'],
                'Booking Reference': ['PNR/Booking Reference', 'Booking Confirmation Number', 'Reference Number', 'Visa Number / Reference', 'Policy Number'],
                'PNR/Booking Reference': ['Booking Reference', 'Booking Confirmation Number', 'Reference Number'],
                'Booking Confirmation Number': ['Booking Reference', 'PNR/Booking Reference', 'Reference Number']
            }
            new_re_data = {}
            for tf in target_fields:
                val = re_data.get(tf, '')
                if not val and tf in FIELD_ALIASES:
                    for alias in FIELD_ALIASES[tf]:
                        if re_data.get(alias):
                            val = re_data[alias]
                            break
                new_re_data[tf] = val
            
            if chosen_type == 'Arrival / Entry Document' and not new_re_data.get('Trip Name'):
                trip_title = d['trip_name'] if ('trip_name' in d.keys() and d['trip_name']) else ''
                if trip_title:
                    new_re_data['Trip Name'] = trip_title
            
            # Clear stale review widget states
            for k in list(st.session_state.keys()):
                if str(k).startswith(f"re_edit_"):
                    del st.session_state[k]

            st.session_state[f'reextract_data_{doc_id}'] = new_re_data
            st.rerun()
            
        target_fields = SCHEMAS.get(chosen_type, ['Document Details'])
        re_data = {tf: re_data.get(tf, '') for tf in target_fields}
        if chosen_type == 'Arrival / Entry Document' and not re_data.get('Trip Name'):
            trip_title = d['trip_name'] if ('trip_name' in d.keys() and d['trip_name']) else ''
            if trip_title:
                re_data['Trip Name'] = trip_title
        updated_re_data = {}
        for k, v in re_data.items():
            updated_re_data[k] = st.text_input(k, value=v, key=f"re_edit_{chosen_type}_{k}")
            
        c1, c2 = st.columns(2)
        if c1.button("Cancel", key=f"cancel_reextract_{doc_id}"):
            st.session_state[f'reextract_mode_{doc_id}'] = False
            st.rerun()
        if c2.button("Confirm & Save Information", key=f"confirm_reextract_{doc_id}"):
            try:
                save_extracted_information(doc_id, updated_re_data, session_token)
                st.session_state[f'reextract_mode_{doc_id}'] = False
                st.success("Information saved.")
                st.rerun()
            except PermissionError as pe:
                st.error(str(pe))
            except ValueError as ve:
                st.error(str(ve))
            except Exception as e:
                st.error(f"Error saving information: {str(e)}")

    else:
        data = json.loads(d['extracted_data']) if d['extracted_data'] and d['extracted_data'] != "{}" else {}
        
        if not data:
            if status == 'Verified':
                st.markdown("**Extracted Information Not Available**")
                st.info("This document was saved before the current extraction workflow. Its original file is preserved, but structured extracted information was not stored.")
                
                is_preview_active = st.session_state.get(f'preview_mode_{doc_id}', False)
                if not is_preview_active:
                    col_p, col_r = st.columns(2)
                    if col_p.button("Preview Extracted Information", key=f"preview_btn_{doc_id}"):
                        st.session_state[f'preview_mode_{doc_id}'] = True
                        st.rerun()
                    if is_reviewer:
                        if col_r.button("Recover Legacy Document Data", key=f"start_recovery_empty_{doc_id}"):
                            initiate_recovery(d, doc_id)
                    else:
                        col_r.info("ℹ️ Supervised recovery requires Supervisor or Admin.")
                else:
                    if is_reviewer:
                        if st.button("Recover Legacy Document Data", key=f"start_recovery_empty_{doc_id}"):
                            initiate_recovery(d, doc_id)
                    else:
                        st.info("ℹ️ Supervised recovery requires Supervisor or Admin.")
                    st.markdown(textwrap.dedent('''
<div style="background:#fff8e1; border:1px solid #ffe082; padding:12px; border-radius:6px; margin-bottom:12px;">
    <strong style="color:#b78103; font-size:1.05rem;">Extracted Preview — Not Saved or Verified</strong><br>
    <small style="color:#555;">This is a read-only preview generated from the stored document file. Extracted data has not been saved to the database and this does not modify the document's Verified status, audit history, or trip readiness.</small>
</div>
'''), unsafe_allow_html=True)
                    
                    if st.button("Close Preview", key=f"close_preview_btn_{doc_id}"):
                        st.session_state[f'preview_mode_{doc_id}'] = False
                        st.rerun()

                    raw_file_path = d['file_path'] if d['file_path'] else ""
                    full_file_path, path_err = get_safe_document_path(raw_file_path)
                    
                    if path_err:
                        st.error(path_err)
                    else:
                        file_bytes = None
                        try:
                            import storage_service
                            st_token = st.session_state.get('session_token')
                            file_bytes = storage_service.read_decrypted_document(full_file_path, session_token=st_token)
                        except Exception as e:
                            st.error(f"Error reading file from disk: {str(e)}")
                            
                        if file_bytes is not None:
                            import document_processor
                            extracted_text = ""
                            if full_file_path.lower().endswith('.pdf'):
                                extracted_text = document_processor.simple_pdf_extract(file_bytes)
                                
                            if not extracted_text or len(extracted_text.strip()) <= 30:
                                st.warning("This document requires OCR processing. External cloud OCR is disabled for this preview without explicit authorization.")
                            else:
                                req_n = d['req_name'] if ('req_name' in d.keys() and d['req_name']) else ''
                                preview_data, preview_conf, detected_type, type_conf = document_processor.parse_passport_text(extracted_text, expected_requirement=req_n)
                                
                                # Check detected type vs requirement
                                expected_type = 'Needs Review'
                                for stype in SUPPORTED_TYPES:
                                    if stype.lower() in req_n.lower():
                                        expected_type = stype
                                        break
                                if expected_type == 'Needs Review':
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
                                        if kw in req_n.lower():
                                            expected_type = target_type
                                            break
                                
                                active_schema_type = detected_type if detected_type in SCHEMAS and detected_type != 'Needs Review' else (expected_type if expected_type in SCHEMAS else 'Needs Review')
                                
                                if active_schema_type == 'Arrival / Entry Document' and not preview_data.get('Trip Name'):
                                    trip_title = d['trip_name'] if ('trip_name' in d.keys() and d['trip_name']) else ''
                                    if trip_title:
                                        preview_data['Trip Name'] = trip_title
                                        preview_conf['Trip Name'] = 'high'
                                
                                st.markdown(f"**Detected Document Type:** `{detected_type}` &nbsp; *(Confidence: **{type_conf}**)*")
                                
                                if expected_type != 'Needs Review' and detected_type != 'Needs Review' and detected_type != expected_type:
                                    st.warning(f"Detected Document Type Mismatch: Engine identified this document as '{detected_type}' (Confidence: {type_conf}), which differs from the expected requirement '{req_n}'.")
                                    
                                target_schema = SCHEMAS.get(active_schema_type, ['Document Details'])
                                
                                missing_fields = []
                                ambiguous_fields = []
                                for fld in target_schema:
                                    val = preview_data.get(fld, '')
                                    if not val or not str(val).strip():
                                        missing_fields.append(fld)
                                    elif preview_conf.get(fld) == 'low':
                                        ambiguous_fields.append(fld)
                                        
                                if missing_fields:
                                    st.markdown(f"<div style='margin-bottom:6px;'><small style='color:#c5221f;'><strong>Missing Fields ({len(missing_fields)}):</strong> {', '.join(missing_fields)}</small></div>", unsafe_allow_html=True)
                                if ambiguous_fields:
                                    st.markdown(f"<div style='margin-bottom:6px;'><small style='color:#b06000;'><strong>Ambiguous / Low Confidence Fields ({len(ambiguous_fields)}):</strong> {', '.join(ambiguous_fields)}</small></div>", unsafe_allow_html=True)
                                    
                                for fld in target_schema:
                                    val = preview_data.get(fld, "")
                                    if not val or not str(val).strip():
                                        label = f"{fld} [Missing]"
                                        disp = "[Not Extracted / Missing in Document]"
                                    elif preview_conf.get(fld) == 'low':
                                        label = f"{fld} [Low Confidence / Ambiguous]"
                                        disp = str(val)
                                    else:
                                        label = f"{fld} [Extracted]"
                                        if fld == 'Aadhaar Number' and val:
                                            disp = services.mask_aadhaar(val) if hasattr(services, 'mask_aadhaar') else str(val)
                                        else:
                                            disp = str(val)
                                    st.text_input(label, value=disp, key=f"preview_field_{doc_id}_{fld}", disabled=True)
                                    
                                extra_fields = [k for k, v in preview_data.items() if v and str(v).strip() and k not in target_schema]
                                for fld in extra_fields:
                                    st.text_input(f"{fld} [Additional Field]", value=str(preview_data[fld]), key=f"preview_field_{doc_id}_{fld}", disabled=True)
            else:
                st.warning("No extracted information is saved for this document. Re-extract information or enter details for review.")
        else:
            req_name = d['req_name'] if ('req_name' in d.keys() and d['req_name']) else ''
            is_arrival = ('arrival' in req_name.lower()) or (req_name == 'Arrival / Entry Document')
            linked_trip = d['trip_name'] if ('trip_name' in d.keys() and d['trip_name']) else ''
            
            if is_arrival:
                arrival_schema_fields = SCHEMAS.get('Arrival / Entry Document', [])
                has_arrival_fields = any(f in data for f in arrival_schema_fields)
                if not has_arrival_fields or 'Passenger Name' in data:
                    st.info("Notice: This document contains legacy extraction data from a previous upload with a different document schema. Sourced booking information is displayed below.")

                stored_trip_name = str(data.get('Trip Name', '')).strip()
                if stored_trip_name and linked_trip:
                    if stored_trip_name.lower() != linked_trip.lower():
                        st.warning(f"Trip Name Discrepancy: Stored Trip Name '{stored_trip_name}' differs from linked booking record '{linked_trip}'.")
                        st.text_input("Trip Name (Stored in Document)", value=stored_trip_name, key=f"edit_trip_stored_{doc_id}", disabled=True)
                        st.text_input("Trip Name (Linked Booking)", value=linked_trip, key=f"edit_trip_linked_{doc_id}", disabled=True)
                    else:
                        st.text_input("Trip Name", value=stored_trip_name, key=f"edit_trip_name_{doc_id}", disabled=True)
                elif linked_trip:
                    st.text_input("Trip Name (Linked Booking)", value=linked_trip, key=f"edit_trip_linked_{doc_id}", disabled=True)
                elif stored_trip_name:
                    st.text_input("Trip Name", value=stored_trip_name, key=f"edit_trip_stored_{doc_id}", disabled=True)

                for k, v in data.items():
                    if k == 'Trip Name':
                        continue
                    st.text_input(k, value=v, key=f"edit_{k}", disabled=True)
            else:
                for k, v in data.items():
                    st.text_input(k, value=v, key=f"edit_{k}", disabled=True)

        if status == 'Verified' and data:
            req_name = d['req_name'] if ('req_name' in d.keys() and d['req_name']) else ''
            req_mandatory = MANDATORY_FIELDS.get(req_name, [])
            is_empty_or_incomplete = any(not str(data.get(m, '')).strip() for m in req_mandatory)
            
            if is_empty_or_incomplete:
                st.markdown(textwrap.dedent('''
                <div style="background:#fef7e0; padding:10px; border-radius:6px; border:1px solid #f9ab00; margin-top:10px; margin-bottom:10px;">
                    <strong>⚠️ Incomplete / Legacy Document Data</strong><br>
                    <small>This Verified document contains legacy or incomplete extracted fields. Supervisors and Admins can perform a supervised recovery to extract and verify the data without reopening the document or degrading trip readiness.</small>
                </div>
                '''), unsafe_allow_html=True)
                
            if is_reviewer:
                if st.button("Recover Legacy Document Data", key=f"start_recovery_btn_{doc_id}"):
                    initiate_recovery(d, doc_id)
            elif is_empty_or_incomplete:
                st.info("ℹ️ Supervised data recovery for Verified documents requires Authorized Reviewer privileges.")
                
        if status in ['Under Review', 'Rejected', 'Re-upload Required']:
            reext_p_kind = None
            if 'passport' in (d['req_name'] or '').lower():
                p_sel = st.radio(
                    "Passport Type for Re-extraction",
                    options=["Indian Passport", "Foreign Passport"],
                    key=f"rev_passport_kind_{doc_id}",
                    horizontal=True,
                )
                reext_p_kind = "foreign" if "Foreign" in p_sel else "indian"

            if st.button("Re-extract Information", key=f"reextract_btn_{doc_id}"):
                import document_processor
                import storage_service
                st_token = st.session_state.get('session_token')
                safe_p, _ = get_safe_document_path(d['file_path'])
                fb = storage_service.read_decrypted_document(
                    safe_p or d['file_path'],
                    session_token=st_token,
                    base_dir=storage_service.get_storage_root(),
                )
                req_val = d['req_name'] if ('req_name' in d.keys() and d['req_name']) else None
                res = document_processor.process_document(
                    d['file_path'],
                    fb,
                    expected_requirement=req_val,
                    passport_kind=reext_p_kind,
                    force_retry=True,
                )
                if res['document_type'] == 'Arrival / Entry Document' and not res['extracted_fields'].get('Trip Name'):
                    trip_title = d['trip_name'] if ('trip_name' in d.keys() and d['trip_name']) else ''
                    if trip_title:
                        res['extracted_fields']['Trip Name'] = trip_title
                st.session_state[f'reextract_data_{doc_id}'] = res['extracted_fields']
                st.session_state[f'reextract_type_{doc_id}'] = res['document_type']
                st.session_state[f'reextract_mode_{doc_id}'] = True
                st.rerun()
        
    if status == 'Under Review':
        st.write("### Actions")
        if is_reviewer:
            if st.session_state.get(f'reject_mode_{doc_id}'):
                st.warning("You are rejecting this document. Please provide a mandatory reason.")
                reject_reason = st.text_input("Mandatory Rejection Reason (Required)", key=f"reject_reason_{doc_id}")
                rc1, rc2 = st.columns(2)
                if rc1.button("Cancel", key=f"cancel_reject_{doc_id}"):
                    st.session_state[f'reject_mode_{doc_id}'] = False
                    st.rerun()
                if rc2.button("Confirm Rejection", type="primary", key=f"confirm_reject_{doc_id}"):
                    if not reject_reason.strip():
                        st.error("Rejection reason is required.")
                    else:
                        try:
                            reject_document(doc_id, reject_reason, session_token)
                            st.session_state[f'reject_mode_{doc_id}'] = False
                            st.warning("Document Rejected.")
                            st.rerun()
                        except Exception as e:
                            st.error(str(e))
            elif st.session_state.get(f'reupload_mode_{doc_id}'):
                st.warning("You are requesting a re-upload for this document. Please provide a mandatory reason.")
                reupload_reason = st.text_input("Mandatory Re-upload Reason (Required)", key=f"reupload_reason_{doc_id}")
                ruc1, ruc2 = st.columns(2)
                if ruc1.button("Cancel", key=f"cancel_reupload_{doc_id}"):
                    st.session_state[f'reupload_mode_{doc_id}'] = False
                    st.rerun()
                if ruc2.button("Confirm Re-upload Request", type="primary", key=f"confirm_reupload_{doc_id}"):
                    if not reupload_reason.strip():
                        st.error("Re-upload reason is required.")
                    else:
                        try:
                            request_reupload_document(doc_id, reupload_reason, session_token)
                            st.session_state[f'reupload_mode_{doc_id}'] = False
                            st.warning("Re-upload Requested.")
                            st.rerun()
                        except Exception as e:
                            st.error(str(e))
            else:
                c1, c2, c3 = st.columns(3)
                if c1.button("Verify Document", type="primary", key=f"verify_btn_{doc_id}"):
                    try:
                        verify_document(d['id'], session_token)
                        st.success("Document Verified!")
                        st.rerun()
                    except Exception as e:
                        st.error(str(e))
                if c2.button("Reject", key=f"reject_btn_{doc_id}"):
                    st.session_state[f'reject_mode_{doc_id}'] = True
                    st.rerun()
                if c3.button("Request Re-upload", key=f"reupload_btn_{doc_id}"):
                    st.session_state[f'reupload_mode_{doc_id}'] = True
                    st.rerun()
        else:
            st.info("ℹ️ Document verification and status management actions (Verify, Reject, Re-upload) require Authorized Reviewer (Operations, Visa, Ticketing, or Administrator) privileges.")
    
    st.write("### Add Note")
    note = st.text_area("Internal staff note about this document")
    if st.button("Save Note", key=f"save_note_{doc_id}"):
        note_str = str(note).strip()
        if note_str:
            try:
                add_document_note(doc_id, note_str, session_token)
                st.success("Note saved.")
                st.rerun()
            except Exception as e:
                st.error(str(e))
