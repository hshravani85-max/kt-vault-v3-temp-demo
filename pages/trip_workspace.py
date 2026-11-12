import streamlit as st
import textwrap
import os
from datetime import datetime
from ui_helpers import inject_custom_css, render_top_nav, render_badge
from services import (
    get_trip_details,
    get_requirements,
    calculate_readiness,
    validate_trip_date_consistency,
    update_trip_dates,
    approve_travel_file,
    generate_trip_travel_pack,
    parse_flexible_date
)
import database
import auth_services

inject_custom_css()
render_top_nav()

trip_id = st.query_params.get('trip_id', 'KT-T-0001')

# Session-state safety: purge stale cached PDF bytes from other trips or sessions
current_session_token = st.session_state.get('session_token')
for k in list(st.session_state.keys()):
    if k.startswith("consolidated_pdf_") or k.startswith("general_travel_pdf_"):
        if not k.endswith(f"_{trip_id}"):
            st.session_state.pop(k, None)

pdf_state_key = f"consolidated_pdf_bytes_{trip_id}"
pdf_name_key = f"consolidated_pdf_name_{trip_id}"
pdf_token_key = f"consolidated_pdf_token_{trip_id}"

if st.session_state.get(pdf_token_key) != current_session_token:
    st.session_state.pop(pdf_state_key, None)
    st.session_state.pop(pdf_name_key, None)
    st.session_state.pop(pdf_token_key, None)

if st.button("← Back to Trips", key="back", icon=":material/arrow_back:"):
    st.session_state['nav_page'] = "trips"
    st.query_params.page = "trips"
    st.rerun()

trip = get_trip_details(trip_id)
if not trip:
    st.error("Trip not found.")
    st.stop()

# Determine user role
user_role = st.session_state.get('user_role')
if not user_role and st.session_state.get('session_token'):
    try:
        user_info = auth_services.get_current_user(st.session_state.get('session_token'))
        if user_info:
            user_role = user_info.get('role')
            st.session_state['user_role'] = user_role
    except Exception:
        pass
can_generate_pack = auth_services.has_permission(current_session_token, "pack:generate") if current_session_token else False
is_reviewer = auth_services.has_permission(current_session_token, "document:verify") if current_session_token else False
is_supervisor_or_admin = is_reviewer or (user_role in ['Supervisor', 'Admin'])

conn = database.get_connection()
trip_travellers = conn.execute("SELECT t.* FROM travellers t JOIN trip_travellers tt ON t.id = tt.traveller_id WHERE tt.trip_id = ?", (trip_id,)).fetchall()
conn.close()
trip_travellers = [dict(t) for t in trip_travellers]
    
reqs = get_requirements(trip_id)
_, comp, att, miss, pct, business_status = calculate_readiness(trip_id)

if business_status != 'TRAVEL FILE READY':
    st.session_state.pop(pdf_state_key, None)
    st.session_state.pop(pdf_name_key, None)
    st.session_state.pop(pdf_token_key, None)

conn = database.get_connection()
c = conn.execute("SELECT name FROM customers WHERE id=?", (trip['customer_id'],)).fetchone()
customer_name = c['name'] if c else "Unknown"
conn.close()

# Enterprise Header & Travel Readiness Banner
st.markdown(textwrap.dedent(f'''
<div style="display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap;">
    <div style="flex: 2; min-width: 340px; background: #FFFFFF; padding: 24px; border-radius: 12px; border: 1px solid #E5EAF1; box-shadow: 0 1px 3px rgba(11,35,72,0.04);">
        <div style="font-size: 0.75rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 1px;">
            TRIP WORKSPACE &nbsp;•&nbsp; <code>{trip['id']}</code>
        </div>
        <h2 style="margin: 4px 0 8px 0; color: #0B2348; font-weight: 800; font-size: 1.7rem;">
            {trip['name']}
        </h2>
        <div style="color: #64748B; font-size: 0.92rem; margin-bottom: 6px;">
            Customer: <strong style="color: #0B2348;">{customer_name}</strong> &nbsp;|&nbsp; 📍 <strong>{trip['destination']}</strong>
        </div>
        <div style="color: #64748B; font-size: 0.88rem;">
            📅 <strong>{trip['start_date']}</strong> to <strong>{trip['end_date']}</strong> &nbsp;|&nbsp; 
            Service: <strong>{trip['service']}</strong> &nbsp;|&nbsp; 
            Dept: <strong>{trip['department']}</strong>
        </div>
    </div>
    <div style="flex: 1; min-width: 260px; background: #FFFFFF; border: 1px solid #E5EAF1; padding: 22px; border-radius: 12px; display: flex; flex-direction: column; justify-content: space-between; box-shadow: 0 1px 3px rgba(11,35,72,0.04);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
                <div style="font-size: 0.8rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.5px;">TRAVEL READINESS</div>
                <div style="margin: 6px 0; font-size: 0.85rem; color: #16A34A; font-weight: 600;">✓ {comp} Complete</div>
                <div style="margin: 3px 0; font-size: 0.85rem; color: #D97706; font-weight: 600;">▲ {att} Pending / Attention</div>
                <div style="margin: 3px 0; font-size: 0.85rem; color: #DC2626; font-weight: 600;">✕ {miss} Action Required</div>
            </div>
            <div style="font-size: 2.2rem; font-weight: 800; color: {'#16A34A' if pct == 100 else '#0875B8'};">{pct}%</div>
        </div>
        <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid #F1F5F9; display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 0.82rem; color: #64748B; font-weight: 600;">STATUS:</span>
            {render_badge(business_status)}
        </div>
    </div>
</div>
'''), unsafe_allow_html=True)

# Evaluate document consistency for stored trip dates
current_date_eval = validate_trip_date_consistency(trip_id, trip['start_date'], trip['end_date'])

# Edit Trip Dates Interface (Supervisor/Admin only, locked when finalized)
curr_start_d = parse_flexible_date(trip.get('start_date')) or datetime.now().date()
curr_end_d = parse_flexible_date(trip.get('end_date')) or datetime.now().date()

if is_supervisor_or_admin and trip.get('status') != 'TRAVEL FILE READY':
    has_conflict = not current_date_eval['compatible']
    with st.expander("✏️ Edit Trip Dates", expanded=has_conflict):
        st.markdown("#### Correct Trip Dates")
        st.markdown(f"**Current Stored Dates:** `{trip['start_date']}` to `{trip['end_date']}`")
        
        c_ed1, c_ed2 = st.columns(2)
        new_start = c_ed1.date_input("New Departure Date *", value=curr_start_d, key=f"edit_start_{trip_id}")
        new_end = c_ed2.date_input("New Return Date *", value=curr_end_d, key=f"edit_end_{trip_id}")
        
        new_start_iso = new_start.strftime("%Y-%m-%d")
        new_end_iso = new_end.strftime("%Y-%m-%d")
        
        if new_end < new_start:
            st.error("Invalid range: Return date cannot be earlier than departure date.")
            can_save_dates = False
        else:
            proposed_eval = validate_trip_date_consistency(trip_id, new_start_iso, new_end_iso)
            if proposed_eval['compatible']:
                num_docs = len(proposed_eval['document_evaluations'])
                if num_docs > 0:
                    st.success(f"✅ Document Consistency Check Passed: All {num_docs} verified document(s) are compatible with proposed dates ({new_start.strftime('%d %b %Y')} – {new_end.strftime('%d %b %Y')}).")
                else:
                    st.success(f"✅ Proposed dates ({new_start.strftime('%d %b %Y')} – {new_end.strftime('%d %b %Y')}) are valid.")
                can_save_dates = True
            else:
                st.error("⚠️ Proposed Dates Conflict With Verified Documents:")
                for conf in proposed_eval['conflicts']:
                    st.markdown(f"- ❌ {conf}")
                can_save_dates = False
                
        edit_reason = st.text_input(
            "Reason for Date Correction * (minimum 5 characters)",
            placeholder="e.g., Corrected departure date to align with verified Emirates flight voucher",
            key=f"edit_reason_{trip_id}"
        )
        
        valid_reason = bool(edit_reason and len(edit_reason.strip()) >= 5)
        dates_changed = (new_start_iso != trip['start_date'] or new_end_iso != trip['end_date'])
        btn_enabled = can_save_dates and valid_reason and dates_changed
        
        if st.button("Confirm & Save Date Correction", type="primary", disabled=not btn_enabled, key=f"btn_save_dates_{trip_id}"):
            try:
                res = update_trip_dates(
                    trip_id=trip_id,
                    new_start_date=new_start_iso,
                    new_end_date=new_end_iso,
                    session_token=st.session_state.get('session_token'),
                    reason=edit_reason.strip(),
                    expected_current_start_date=trip['start_date'],
                    expected_current_end_date=trip['end_date']
                )
                st.success(f"Trip dates successfully updated to {new_start_iso} – {new_end_iso}.")
                st.rerun()
            except Exception as e:
                st.error(f"Failed to update trip dates: {e}")
                
        if not valid_reason and dates_changed:
            st.caption("ℹ️ A non-empty correction reason of at least 5 characters is required.")
        elif not dates_changed:
            st.caption("ℹ️ Modify departure or return date to enable saving.")

elif trip.get('status') == 'TRAVEL FILE READY':
    st.info("🔒 **Trip Dates Locked**: Travel file is approved and ready. Dates cannot be modified.")

# Business Status Actions
if business_status == 'READY FOR FINAL REVIEW':
    if not current_date_eval['compatible']:
        st.error("🚨 **Final Approval Blocked: Material Trip Date Conflict Detected**")
        st.markdown(
            f"The trip's stored dates (**{trip['start_date']}** to **{trip['end_date']}**) conflict with verified travel documents. "
            "A Supervisor or Admin must correct the trip dates before the travel file can be approved."
        )
        for conf in current_date_eval['conflicts']:
            st.markdown(f"- ❌ {conf}")
    else:
        st.info("All documents are verified and trip dates are consistent. This trip is ready for final approval.")
        if is_reviewer:
            if st.button("Approve Travel File", type="primary"):
                st.session_state['confirm_approval'] = True

            if st.session_state.get('confirm_approval'):
                st.warning("Are you sure you want to approve this travel file?")
                c1, c2 = st.columns(2)
                if c1.button("Confirm Approval", type="primary"):
                    try:
                        res = approve_travel_file(trip_id, st.session_state.get('session_token'))
                        st.session_state['confirm_approval'] = False
                        st.success("Travel File Approved successfully.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Approval failed: {e}")
                if c2.button("Cancel"):
                    st.session_state['confirm_approval'] = False
                    st.rerun()
        else:
            st.caption("Approval requires Authorized Reviewer (Operations, Visa, Ticketing, or Administrator) privileges.")

elif business_status == 'TRAVEL FILE READY':
    st.success("Travel File is Approved and Ready.")
    
    if can_generate_pack:
        c_gen, c_dl = st.columns([1, 1])
        with c_gen:
            if st.button("Generate & Download Travel File", type="primary", key=f"btn_gen_pdf_{trip_id}"):
                session_token = st.session_state.get('session_token')
                try:
                    generated_path = generate_trip_travel_pack(trip_id, session_token)
                    if not generated_path or not os.path.exists(generated_path) or os.path.getsize(generated_path) == 0:
                        st.session_state.pop(pdf_state_key, None)
                        st.session_state.pop(pdf_name_key, None)
                        st.session_state.pop(pdf_token_key, None)
                        st.error("Error: Generated travel file is empty or missing.")
                    else:
                        import storage_service
                        st.session_state[pdf_state_key] = storage_service.read_decrypted_document(
                            generated_path, session_token=session_token
                        )
                        st.session_state[pdf_name_key] = f"TravelFile_{trip_id}.pdf"
                        st.session_state[pdf_token_key] = session_token
                        st.success("Consolidated Travel File generated successfully.")
                except PermissionError as pe:
                    st.session_state.pop(pdf_state_key, None)
                    st.session_state.pop(pdf_name_key, None)
                    st.session_state.pop(pdf_token_key, None)
                    st.error(f"Permission denied: {pe}")
                except Exception as e:
                    st.session_state.pop(pdf_state_key, None)
                    st.session_state.pop(pdf_name_key, None)
                    st.session_state.pop(pdf_token_key, None)
                    st.error("An error occurred while generating the travel file. Please check system logs.")

        with c_dl:
            pdf_bytes = st.session_state.get(pdf_state_key)
            if pdf_bytes and st.session_state.get(pdf_token_key) == st.session_state.get('session_token') and can_generate_pack:
                dl_filename = st.session_state.get(pdf_name_key, f"TravelFile_{trip_id}.pdf")
                st.download_button(
                    label="📥 Download Travel File",
                    data=pdf_bytes,
                    file_name=dl_filename,
                    mime="application/pdf",
                    key=f"dl_consolidated_{trip_id}",
                    use_container_width=True
                )
    else:
        st.caption("Consolidated Travel File generation requires authorized office staff privileges.")

tabs = st.tabs([
    "Document Checklist",
    "Trip Itinerary",
    "Traveller",
    "Trip Details",
    "Notes",
    "Activity"
])

with tabs[0]:
    def prepare_upload_session(target_trip_id, req_id=None):
        import uuid
        st.session_state['upload_step'] = 1
        for k in ['uploaded_filename', 'upload_safe_path', 'extracted_result', 'smart_upload_confirmed_type']:
            st.session_state.pop(k, None)
        st.session_state['upload_version'] = st.session_state.get('upload_version', 0) + 1
        st.session_state['upload_instance_id'] = uuid.uuid4().hex[:8]
        for k in list(st.session_state.keys()):
            if str(k).startswith("smart_up_") or str(k).startswith("file_uploader_") or k == "confirm_doc_type_select":
                st.session_state.pop(k, None)
        st.session_state['upload_trip_id'] = target_trip_id
        if req_id:
            st.session_state['upload_req_id'] = req_id
        else:
            st.session_state.pop('upload_req_id', None)
        st.session_state['nav_page'] = "smart_upload"
        st.query_params.page = "smart_upload"
        st.rerun()

    c1, c2 = st.columns([3, 1])
    with c1:
        st.markdown('<div class="kt-section-title">👤 Traveller Documents</div>', unsafe_allow_html=True)
    with c2:
        if st.button("📤 Smart Upload", key="trip_smart_upload", use_container_width=True, type="primary"):
            prepare_upload_session(trip_id, None)

    for t in trip_travellers:
        st.markdown(f"<div style='background:#F1F5F9; padding:8px 14px; border-radius:8px; margin:14px 0 10px 0; font-weight:700; color:#0B2348;'>👤 {t['name']}</div>", unsafe_allow_html=True)
        
        t_reqs = [r for r in reqs if r['type'] == 'TRAVELLER' and r['traveller_id'] == t['id']]
        if not t_reqs:
            st.write("No traveller documents required.")
        for r in t_reqs:
            status = r.get('doc_status') or 'Missing'
            with st.container():
                c1, c2, c3 = st.columns([1, 4.5, 2])
                c1.markdown("<div style='font-size:1.4rem; padding-top:4px;'>📄</div>", unsafe_allow_html=True)
                c2.markdown(f"**{r['name']}**<br>{render_badge(status)}", unsafe_allow_html=True)
                with c3:
                    if status == 'Missing':
                        if st.button("Add Document", key=f"add_{r['id']}", use_container_width=True):
                            prepare_upload_session(trip_id, r['id'])
                    elif status == 'Under Review':
                        if st.button("Review", key=f"rev_{r['id']}", use_container_width=True):
                            st.query_params.doc_id = r['doc_id']
                            st.session_state['nav_page'] = "document_review"
                            st.query_params.page = "document_review"
                            st.rerun()
                    elif status == 'Verified':
                        if st.button("View", key=f"view_{r['id']}", use_container_width=True):
                            st.query_params.doc_id = r['doc_id']
                            st.session_state['nav_page'] = "document_review"
                            st.query_params.page = "document_review"
                            st.rerun()
                    else:
                        if st.button("Replace Document", key=f"rep_{r['id']}", use_container_width=True):
                            prepare_upload_session(trip_id, r['id'])
                st.markdown("<hr style='margin:10px 0; border:none; border-top:1px solid #E5EAF1;'>", unsafe_allow_html=True)

    st.markdown('<div class="kt-section-title">✈️ Trip Documents</div>', unsafe_allow_html=True)
    trip_reqs = [r for r in reqs if r['type'] == 'TRIP']
    for r in trip_reqs:
        status = r.get('doc_status') or 'Missing'
        with st.container():
            c1, c2, c3 = st.columns([1, 4.5, 2])
            c1.markdown("<div style='font-size:1.4rem; padding-top:4px;'>🎫</div>", unsafe_allow_html=True)
            c2.markdown(f"**{r['name']}**<br>{render_badge(status)}", unsafe_allow_html=True)
            with c3:
                if status == 'Missing':
                    if st.button("Add Document", key=f"add_{r['id']}", use_container_width=True):
                        prepare_upload_session(trip_id, r['id'])
                elif status == 'Under Review':
                    if st.button("Review", key=f"rev_{r['id']}", use_container_width=True):
                        st.query_params.doc_id = r['doc_id']
                        st.session_state['nav_page'] = "document_review"
                        st.query_params.page = "document_review"
                        st.rerun()
                elif status == 'Verified':
                    if st.button("View", key=f"view_{r['id']}", use_container_width=True):
                        st.query_params.doc_id = r['doc_id']
                        st.session_state['nav_page'] = "document_review"
                        st.query_params.page = "document_review"
                        st.rerun()
                else:
                    if st.button("Replace Document", key=f"rep_{r['id']}", use_container_width=True):
                        prepare_upload_session(trip_id, r['id'])
            st.markdown("<hr style='margin:10px 0; border:none; border-top:1px solid #E5EAF1;'>", unsafe_allow_html=True)

conn = database.get_connection()
acts = conn.execute("SELECT * FROM activity WHERE trip_id=? ORDER BY timestamp DESC", (trip_id,)).fetchall()
conn.close()

with tabs[1]:
    st.markdown('<div class="kt-section-title">📅 Trip Itinerary</div>', unsafe_allow_html=True)
    st.markdown(f"**Destination:** {trip['destination']} &nbsp;|&nbsp; **Dates:** {trip['start_date']} to {trip['end_date']}")
    itin_reqs = [r for r in reqs if 'Itinerary' in r['name'] or r.get('doc_type') == 'Itinerary']
    if itin_reqs:
        for ir in itin_reqs:
            st.markdown(f"- **{ir['name']}** — {render_badge(ir.get('doc_status') or 'Missing')}", unsafe_allow_html=True)
    else:
        st.info("No specific itinerary document requirements attached. Refer to travel vouchers in the Document Checklist.")

with tabs[2]:
    st.markdown('<div class="kt-section-title">👥 Travellers Assigned to Trip</div>', unsafe_allow_html=True)
    if not trip_travellers:
        st.info("No travellers assigned.")
    for t in trip_travellers:
        with st.container(border=True):
            col_t1, col_t2 = st.columns([3, 1.2])
            with col_t1:
                st.markdown(f"#### 👤 {t['name']}")
                st.markdown(
                    f"**DOB:** {t.get('dob') or 'Not provided'} &nbsp;•&nbsp; "
                    f"**Nationality:** {t.get('nationality') or 'Not provided'}"
                )
            with col_t2:
                st.caption("Passport Number")
                pass_no = t.get('passport_number')
                if pass_no and pass_no != 'Not provided':
                    st.code(pass_no, language=None)
                else:
                    st.write("Not provided")

with tabs[3]:
    st.markdown('<div class="kt-section-title">ℹ️ Trip Details & Metadata</div>', unsafe_allow_html=True)
    st.markdown(f"""
    - **Trip ID:** `{trip['id']}`
    - **Trip Name:** {trip['name']}
    - **Customer:** {customer_name} (`{trip['customer_id']}`)
    - **Destination:** {trip['destination']}
    - **Departure Date:** `{trip['start_date']}`
    - **Return Date:** `{trip['end_date']}`
    - **Service Type:** {trip.get('service', 'N/A')}
    - **Department:** {trip.get('department', 'N/A')}
    - **Trip Status:** `{trip.get('status', 'DRAFT')}`
    """)
    if trip.get('status') == 'TRAVEL FILE READY':
        st.info("🔒 This trip is finalized. Trip dates cannot be modified.")
    elif is_supervisor_or_admin:
        st.caption("ℹ️ To adjust departure or return dates, expand the '✏️ Edit Trip Dates' section above.")

with tabs[4]:
    st.markdown('<div class="kt-section-title">📝 Internal Notes</div>', unsafe_allow_html=True)
    note = st.text_area("Add internal staff note for this trip")
    if st.button("Save Note"):
        note_str = str(note).strip()
        if note_str:
            conn = database.get_connection()
            conn.execute("INSERT INTO activity (trip_id, description, timestamp) VALUES (?, ?, ?)", 
                         (trip_id, f"Note added: {note_str}", datetime.now().isoformat()))
            conn.commit()
            conn.close()
            st.success("Note saved.")
            st.rerun()
        else:
            st.error("Cannot save an empty note.")
    
    st.write("#### Existing Notes")
    for a in acts:
        st.write(f"- {a['timestamp'][:19]}: {a['description']}")

with tabs[5]:
    st.markdown('<div class="kt-section-title">⏱️ Activity History</div>', unsafe_allow_html=True)
    for a in acts:
        st.write(f"{a['timestamp'][:19]}: {a['description']}")
