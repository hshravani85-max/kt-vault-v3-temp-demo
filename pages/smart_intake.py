import streamlit as st
import os
import json
import uuid
from datetime import datetime
import services
import database
from ui_helpers import inject_custom_css, render_top_nav, render_badge

inject_custom_css()
render_top_nav()

# Page Header
st.markdown('<h1 style="color:#0B2348; margin:0; font-size:2rem; font-weight:800;">Smart Intake</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#64748B; margin:4px 0 16px 0; font-size:0.95rem;">Automated customer registration and passport extraction with OCR verification.</p>', unsafe_allow_html=True)

if 'intake_step' not in st.session_state:
    st.session_state['intake_step'] = 1

def reset_intake():
    if not st.session_state.get('intake_completed', False):
        if 'intake_safe_path' in st.session_state:
            safe_path = st.session_state['intake_safe_path']
            if safe_path and os.path.exists(safe_path):
                try: os.remove(safe_path)
                except: pass

    keys_to_clear = [
        'intake_step', 'intake_file_name', 'intake_safe_path',
        'intake_extracted', 'intake_warnings', 'intake_confidence',
        'intake_doc_type', 'intake_selected_customer', 'intake_match_found',
        'intake_customer_data', 'intake_idempotency_key', 'intake_completed',
        'intake_result', 'intake_passport_kind', 'intake_can_retry_azapi',
        'intake_manual_review', 'intake_source_type'
    ]
    for k in keys_to_clear:
        if k in st.session_state:
            del st.session_state[k]

# Cancel action
if st.button("← Cancel Intake", key="cancel_intake", icon=":material/arrow_back:"):
    reset_intake()
    st.session_state['nav_page'] = "customers"
    st.query_params.page = "customers"
    st.rerun()

step = st.session_state['intake_step']

# Visual Step Progress Indicator
steps_def = [
    (1, "1. Upload"),
    (2, "2. Confirm Details"),
    (3, "3. Customer Match"),
    (4, "4. Complete")
]
step_chips = []
for num, s_title in steps_def:
    if num == step:
        s_style = "background:#0875B8; color:#FFFFFF; font-weight:700; border:1px solid #0875B8;"
        txt_c = "#0875B8"
    elif num < step:
        s_style = "background:#DCFCE7; color:#15803D; font-weight:700; border:1px solid #BBF7D0;"
        txt_c = "#15803D"
    else:
        s_style = "background:#F1F5F9; color:#64748B; font-weight:600; border:1px solid #E2E8F0;"
        txt_c = "#64748B"
    badge_label = "✓" if num < step else str(num)
    step_chips.append(f"<div style='display:inline-flex; align-items:center; gap:6px;'><span style='width:24px; height:24px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; font-size:0.78rem; {s_style}'>{badge_label}</span><span style='font-size:0.85rem; font-weight:600; color:{txt_c};'>{s_title}</span></div>")

chips_html = ' <span style="color:#CBD5E1;">&gt;</span> '.join(step_chips)
st.markdown(f"<div style='background:#FFFFFF; border:1px solid #E5EAF1; border-radius:10px; padding:12px 18px; margin-bottom:20px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;'>{chips_html}</div>", unsafe_allow_html=True)

if step == 1:
    st.markdown('<div class="kt-section-title">Step 1: Upload Travel Identity Document</div>', unsafe_allow_html=True)
    st.info("Upload a passport or supported travel document (PDF or image). KT Vault will extract available traveller details for your verification.")

    passport_origin = st.radio(
        "Passport Type (Required for AZAPI Routing)",
        options=["Indian Passport", "Foreign Passport"],
        key="intake_passport_origin_radio",
        horizontal=True,
    )
    passport_kind = "foreign" if "Foreign" in passport_origin else "indian"

    uploaded_file = st.file_uploader(
        "Upload Passport (PDF, JPG, JPEG, PNG - Max 20MB for AZAPI / 25MB Vault Limit)",
        type=['pdf', 'jpg', 'png', 'jpeg']
    )

    if st.button("Upload & Extract Information", type="primary", disabled=not uploaded_file, icon=":material/document_scanner:"):
        raw_bytes = uploaded_file.getvalue()
        if len(raw_bytes) > services.MAX_DOCUMENT_SIZE_BYTES:
            st.error(f"File exceeds maximum Vault size of {services.MAX_DOCUMENT_SIZE_BYTES // (1024 * 1024)}MB.")
            st.stop()

        import document_processor
        import uuid
        import os
        import storage_service

        st.session_state['intake_file_name'] = uploaded_file.name
        st.session_state['intake_passport_kind'] = passport_kind

        ext = os.path.splitext(uploaded_file.name)[1].lower()
        if not ext:
            ext = ".pdf"
        safe_filename = f"intake_{uuid.uuid4().hex}{ext}"
        docs_root = storage_service.get_storage_root()
        os.makedirs(docs_root, exist_ok=True)
        physical_path = os.path.join(docs_root, safe_filename)
        safe_path = f"documents/{safe_filename}"

        st_token = st.session_state.get('session_token')
        storage_service.write_document_file(
            physical_path,
            raw_bytes,
            session_token=st_token,
            base_dir=docs_root,
        )

        st.session_state['intake_safe_path'] = safe_path
        st.session_state['intake_idempotency_key'] = f"op_{uuid.uuid4().hex}"
        st.session_state['intake_completed'] = False

        result = document_processor.process_document(
            uploaded_file.name,
            raw_bytes,
            expected_requirement="Passport",
            passport_kind=passport_kind,
            session_token=st_token,
            require_auth=True,
        )

        extracted_fields = result.get('extracted_fields', {})
        st.session_state['intake_extracted'] = extracted_fields
        st.session_state['intake_warnings'] = result.get('warnings', [])
        st.session_state['intake_confidence'] = result.get('confidence', {})
        st.session_state['intake_doc_type'] = result.get('document_type', 'Needs Review')
        st.session_state['intake_can_retry_azapi'] = bool(result.get('can_retry_azapi', False))
        st.session_state['intake_manual_review'] = bool(result.get('manual_review_required', False))
        st.session_state['intake_source_type'] = result.get('source_type', '')

        # Pre-populate explicit widget session state keys for Step 2
        for field_key, field_val in extracted_fields.items():
            st.session_state[f"intake_input_{field_key}"] = field_val

        st.session_state['intake_step'] = 2
        st.rerun()

elif step == 2:
    st.markdown('<div class="kt-section-title">Step 2: Confirm Extracted Information</div>', unsafe_allow_html=True)
    doc_type = st.session_state.get('intake_doc_type', 'Needs Review')
    if doc_type == 'Passport':
        st.success(f"**DOCUMENT DETECTED**: {doc_type}")
    else:
        st.warning(f"**DOCUMENT DETECTED**: {doc_type}")

    if st.session_state.get('intake_manual_review'):
        st.warning("Manual Review Required: Please enter or verify traveller passport details manually.")

    if st.session_state.get('intake_warnings'):
        for w in st.session_state['intake_warnings']:
            st.warning(w)

    if st.session_state.get('intake_can_retry_azapi'):
        if st.button("🔄 Retry AZAPI Extraction", key="intake_retry_azapi_btn", help="Explicit manual retry (zero automatic retries)."):
            import document_processor
            import storage_service
            safe_p, _ = services.get_safe_document_path(st.session_state.get('intake_safe_path'))
            fb = storage_service.read_decrypted_document(
                safe_p or st.session_state.get('intake_safe_path'),
                session_token=st.session_state.get('session_token'),
                base_dir=storage_service.get_storage_root(),
            )
            retried = document_processor.process_document(
                st.session_state.get('intake_file_name', 'passport.jpg'),
                fb,
                expected_requirement="Passport",
                passport_kind=st.session_state.get('intake_passport_kind', 'indian'),
                force_retry=True,
                session_token=st.session_state.get('session_token'),
                require_auth=True,
            )
            ext_f = retried.get('extracted_fields', {})
            st.session_state['intake_extracted'] = ext_f
            st.session_state['intake_warnings'] = retried.get('warnings', [])
            st.session_state['intake_confidence'] = retried.get('confidence', {})
            st.session_state['intake_doc_type'] = retried.get('document_type', 'Needs Review')
            st.session_state['intake_can_retry_azapi'] = bool(retried.get('can_retry_azapi', False))
            st.session_state['intake_manual_review'] = bool(retried.get('manual_review_required', False))
            for k, v in ext_f.items():
                st.session_state[f"intake_input_{k}"] = v
            st.rerun()

    st.markdown("Please verify the extracted information below before saving to the customer profile.")

    ext = st.session_state.get('intake_extracted', {})
    conf = st.session_state.get('intake_confidence', {})

    def sanitize_ui_value(val):
        if not val or not isinstance(val, str):
            return ""
        clean = "".join(ch for ch in val if ch.isprintable() or ch in ('\n', ' '))
        return clean.strip()

    def render_field(label, key):
        val = st.session_state.get(f"intake_input_{key}", sanitize_ui_value(ext.get(key, "")))
        c = conf.get(key, "low")
        if c == "low" or not val:
            display_label = f"{label} (⚠️ Confirm)"
            help_text = f"Please confirm or enter the {label} manually from document."
        elif c == "high":
            display_label = f"{label} (✓ Verified)"
            help_text = f"Automatically verified with high confidence."
        else:
            display_label = label
            help_text = None
        return st.text_input(display_label, value=val, key=f"intake_input_{key}", help=help_text)

    with st.form("confirm_details_form"):
        col1, col2 = st.columns(2)
        with col1:
            full_name = render_field("Full Name", "Full Name")
            dob = render_field("Date of Birth", "Date of Birth")
            nationality = render_field("Nationality", "Nationality")
        with col2:
            pass_num = render_field("Passport Number", "Passport Number")
            issue = render_field("Issue Date", "Issue Date")
            expiry = render_field("Expiry Date", "Expiry Date")
            place = render_field("Place of Issue", "Place of Issue")

        if st.form_submit_button("Confirm & Proceed", type="primary"):
            st.session_state['intake_extracted'] = {
                "Full Name": full_name,
                "Date of Birth": dob,
                "Nationality": nationality,
                "Passport Number": pass_num,
                "Issue Date": issue,
                "Expiry Date": expiry,
                "Place of Issue": place
            }
            st.session_state['intake_step'] = 3
            st.rerun()

elif step == 3:
    st.markdown('<div class="kt-section-title">Step 3: Customer Matching & Creation</div>', unsafe_allow_html=True)
    ext = st.session_state['intake_extracted']

    conn = database.get_connection()
    matches = conn.execute("SELECT id, name, customer_type FROM customers WHERE name LIKE ?", (f"%{ext['Full Name']}%",)).fetchall()
    conn.close()

    st.write(f"**Extracted Traveller Name**: {ext['Full Name']}")
    st.write(f"**Passport Number**: {ext['Passport Number']}")

    if matches:
        st.warning("POSSIBLE EXISTING CUSTOMER FOUND")
        for m in matches:
            st.write(f"- **{m['name']}** (Customer ID: {m['id']}) - {m['customer_type']}")
            if st.button(f"Use Existing Customer ({m['id']})", key=f"use_{m['id']}"):
                st.session_state['intake_selected_customer'] = m['id']
                st.session_state['intake_customer_data'] = None
                st.session_state['intake_step'] = 4
                st.rerun()

        st.markdown("<hr>", unsafe_allow_html=True)
        st.write("Or create a new customer record:")
    else:
        st.info("No existing customer matches found.")

    with st.form("create_new_customer_form"):
        st.write("#### Create New Customer")
        c_name = st.text_input("Customer Name", value=ext['Full Name'])
        c_mob = st.text_input("Mobile Number (Optional)")
        c_em = st.text_input("Email Address (Optional)")
        c_type = st.selectbox("Customer Type", ["Individual", "Family", "Corporate", "Group"])

        if st.form_submit_button("Create Customer & Traveller", type="primary"):
            if not c_name.strip():
                st.error("Customer Name is required.")
            else:
                st.session_state['intake_customer_data'] = {
                    'name': c_name.strip(),
                    'mobile': c_mob.strip() if c_mob.strip() else None,
                    'email': c_em.strip() if c_em.strip() else None,
                    'customer_type': c_type
                }
                st.session_state['intake_selected_customer'] = None
                st.session_state['intake_step'] = 4
                st.rerun()

elif step == 4:
    st.markdown('<div class="kt-section-title">Step 4: Finalizing Traveller & Document</div>', unsafe_allow_html=True)

    ext = st.session_state.get('intake_extracted', {})
    cust_id = st.session_state.get('intake_selected_customer')
    c_data = st.session_state.get('intake_customer_data')
    safe_path = st.session_state.get('intake_safe_path')
    op_id = st.session_state.get('intake_idempotency_key')

    resolved_intake_path, _ = services.get_safe_document_path(safe_path)
    if not safe_path or not (resolved_intake_path or os.path.exists(safe_path)):
        st.error("Uploaded document file was not found on disk. Please restart intake.")
        if st.button("Restart Intake"):
            reset_intake()
            st.session_state['intake_step'] = 1
            st.rerun()
        st.stop()

    if not st.session_state.get('intake_completed', False):
        with st.spinner("Finalizing customer, traveller profile, and document..."):
            try:
                trav_data = {
                    'name': ext.get('Full Name', ''),
                    'dob': ext.get('Date of Birth'),
                    'traveller_type': "Adult",
                    'relationship': "Self",
                    'lead_traveller': True,
                    'passport_number': ext.get('Passport Number'),
                    'nationality': ext.get('Nationality')
                }
                result = services.complete_smart_intake(
                    customer_id=cust_id,
                    customer_data=c_data,
                    traveller_data=trav_data,
                    document_fields=ext,
                    file_path=safe_path,
                    session_token=st.session_state.get('session_token'),
                    idempotency_key=op_id
                )
                st.session_state['intake_result'] = result
                st.session_state['intake_completed'] = True
                st.session_state['intake_selected_customer'] = result['customer_id']
            except Exception as e:
                st.error(f"Error finalizing Smart Intake: {e}")
                st.stop()

    res = st.session_state.get('intake_result', {})
    target_c_id = res.get('customer_id') or st.session_state.get('intake_selected_customer')

    if res.get('reused'):
        st.info("Notice: Matching traveller and document were already registered for this customer. Existing profile was preserved.")
    else:
        st.success(f"Successfully added Traveller {ext.get('Full Name', '')} and stored Passport!")

    if st.button("Go to Customer Workspace", type="primary", key="btn_go_cust_workspace"):
        reset_intake()
        st.query_params.customer_id = target_c_id
        st.session_state['nav_page'] = "customer_workspace"
        st.query_params.page = "customer_workspace"
        st.rerun()

