import streamlit as st
from ui_helpers import (
    inject_custom_css,
    render_top_nav,
    render_badge,
    render_kpi_card,
    render_welcome_banner
)
import services
from services import get_all_documents_for_review, calculate_readiness
import database

inject_custom_css()
render_top_nav()

# 1. Professional Travel Photography Welcome Banner
render_welcome_banner()

# 2. Database Metrics Calculation
conn = database.get_connection()

need_review_count = conn.execute("SELECT count(*) FROM documents WHERE status = 'Under Review'").fetchone()[0]

missing_count = conn.execute('''
    SELECT count(*) FROM requirements r
    LEFT JOIN documents d ON r.id = d.requirement_id
    WHERE d.id IS NULL OR d.status IN ('Replace Required', 'Action Required')
''').fetchone()[0]

reupload_count = conn.execute("SELECT count(*) FROM documents WHERE status = 'Re-upload Required'").fetchone()[0]

readiness_trip_rows = conn.execute("SELECT id FROM trips").fetchall()

ready_for_review_count = 0
for t in readiness_trip_rows:
    _, _, _, _, _, business_status = calculate_readiness(t['id'])
    if business_status == 'READY FOR FINAL REVIEW':
        ready_for_review_count += 1

# Check for expiring soon / validity alerts from documents if available
validity_alerts_count = 0
expiring_soon_count = 0

trips = conn.execute('''
    SELECT t.*, c.name as customer_name
    FROM trips t
    LEFT JOIN customers c ON t.customer_id = c.id
    ORDER BY t.start_date ASC
''').fetchall()

conn.close()

# 3. Mandatory Document Compliance Summary
mand_metrics = services.get_dashboard_mandatory_metrics()

st.markdown('<div class="kt-section-title">🪪 Mandatory Document Compliance (Aadhaar & PAN Vault)</div>', unsafe_allow_html=True)
m_kpi_cols = st.columns(5)
with m_kpi_cols[0]:
    st.markdown(render_kpi_card("Total Customers", mand_metrics['total_customers'], color="#0B2348", icon="👥"), unsafe_allow_html=True)
with m_kpi_cols[1]:
    st.markdown(render_kpi_card("Both Verified (2/2)", mand_metrics['both_verified_count'], color="#16A34A", icon="✅"), unsafe_allow_html=True)
with m_kpi_cols[2]:
    st.markdown(render_kpi_card("Missing Documents", mand_metrics['missing_either_count'], color="#DC2626", icon="⚠️"), unsafe_allow_html=True)
with m_kpi_cols[3]:
    st.markdown(render_kpi_card("Pending Review", mand_metrics['pending_verification_count'], color="#2563EB", icon="⏳"), unsafe_allow_html=True)
with m_kpi_cols[4]:
    st.markdown(render_kpi_card("Rejected", mand_metrics['rejected_count'], color="#DC2626", icon="✕"), unsafe_allow_html=True)

with st.expander("🔍 View Mandatory Compliance Breakdown by Customer"):
    f_col1, f_col2 = st.columns([2, 2])
    with f_col1:
        dash_comp_filter = st.selectbox(
            "Filter Customers",
            ["All", "Missing Either", "Missing Aadhaar", "Missing PAN", "Pending Verification", "Rejected", "Fully Complete (2/2)"],
            key="dash_comp_filter_key"
        )
    
    shown_custs = []
    for row in mand_metrics['customer_list']:
        a_s = row['aadhaar_status']
        p_s = row['pan_status']
        if dash_comp_filter == "Fully Complete (2/2)" and not row['is_complete']:
            continue
        if dash_comp_filter == "Missing Either" and not (a_s == 'Missing' or p_s == 'Missing'):
            continue
        if dash_comp_filter == "Missing Aadhaar" and a_s != 'Missing':
            continue
        if dash_comp_filter == "Missing PAN" and p_s != 'Missing':
            continue
        if dash_comp_filter == "Pending Verification" and not (a_s == 'Pending Verification' or p_s == 'Pending Verification'):
            continue
        if dash_comp_filter == "Rejected" and not (a_s == 'Rejected' or p_s == 'Rejected'):
            continue
        shown_custs.append(row)

    if not shown_custs:
        st.info("No customers match the selected compliance filter.")
    else:
        st.caption(f"Showing {len(shown_custs)} customer accounts")
        for sc in shown_custs:
            row_c1, row_c2, row_c3, row_c4 = st.columns([2, 3, 3, 2])
            with row_c1:
                st.markdown(f"<code>{sc['id']}</code>", unsafe_allow_html=True)
            with row_c2:
                st.markdown(f"**{sc['name']}**")
            with row_c3:
                a_badge = render_badge(sc['aadhaar_status'])
                p_badge = render_badge(sc['pan_status'])
                st.markdown(f"<div style='font-size:0.8rem;'>Aadhaar: {a_badge} &nbsp;|&nbsp; PAN: {p_badge}</div>", unsafe_allow_html=True)
            with row_c4:
                if st.button("Open Vault", key=f"dash_open_{sc['id']}", use_container_width=True):
                    st.query_params.customer_id = sc['id']
                    st.session_state['nav_page'] = "customer_workspace"
                    st.query_params.page = "customer_workspace"
                    st.rerun()

# 4. Document & Trip Metrics
st.markdown('<div class="kt-section-title">📊 Trip & Operations Metrics</div>', unsafe_allow_html=True)

kpi_cols = st.columns(6)
with kpi_cols[0]:
    st.markdown(render_kpi_card("Need Review", need_review_count, color="#2563EB", icon="📄"), unsafe_allow_html=True)
with kpi_cols[1]:
    st.markdown(render_kpi_card("Missing Documents", missing_count, color="#DC2626", icon="⚠️"), unsafe_allow_html=True)
with kpi_cols[2]:
    st.markdown(render_kpi_card("Validity Alerts", validity_alerts_count, color="#F59E0B", icon="🔔"), unsafe_allow_html=True)
with kpi_cols[3]:
    st.markdown(render_kpi_card("Expiring Soon", expiring_soon_count, color="#F59E0B", icon="⏳"), unsafe_allow_html=True)
with kpi_cols[4]:
    st.markdown(render_kpi_card("Re-upload Req.", reupload_count, color="#DC2626", icon="🔄"), unsafe_allow_html=True)
with kpi_cols[5]:
    st.markdown(render_kpi_card("Ready for Review", ready_for_review_count, color="#16A34A", icon="✅"), unsafe_allow_html=True)

# 4. Quick Actions
st.markdown('<div class="kt-section-title">⚡ Quick Actions</div>', unsafe_allow_html=True)
qa_cols = st.columns(4)
with qa_cols[0]:
    if st.button("➕ Add Customer", key="qa_add_cust", use_container_width=True):
        st.session_state['show_add_customer'] = True
        st.session_state['nav_page'] = "customers"
        st.query_params.page = "customers"
        st.rerun()
with qa_cols[1]:
    if st.button("✈️ View Trips", key="qa_view_trips", use_container_width=True):
        st.session_state['nav_page'] = "trips"
        st.query_params.page = "trips"
        st.rerun()
with qa_cols[2]:
    if st.button("📤 Smart Upload", key="qa_smart_upload", use_container_width=True):
        st.session_state['nav_page'] = "smart_upload"
        st.query_params.page = "smart_upload"
        st.rerun()
with qa_cols[3]:
    if st.button("🔍 Search Documents", key="qa_search_docs", use_container_width=True):
        st.session_state['nav_page'] = "vault_search"
        st.query_params.page = "vault_search"
        st.rerun()

# 5. Upcoming Trips
st.markdown('<div class="kt-section-title">✈️ Upcoming Trips</div>', unsafe_allow_html=True)

if not trips:
    st.info("No upcoming trips found.")
else:
    for t in trips:
        tot, comp, att, miss, pct, b_status = calculate_readiness(t['id'])
        dest_icon = "🏰" if "Dubai" in (t['destination'] or '') else ("🌆" if "Singapore" in (t['destination'] or '') else "✈️")
        
        with st.container(border=True):
            c_icon, c_info, c_action = st.columns([0.8, 6, 2])
            with c_icon:
                st.markdown(f"<div style='font-size:2rem; text-align:center; padding-top:6px;'>{dest_icon}</div>", unsafe_allow_html=True)
            with c_info:
                st.markdown(f"#### {t['customer_name'] or 'Unknown Customer'} — {t['name']}")
                st.markdown(f"📅 {t['start_date']} to {t['end_date']} &nbsp;|&nbsp; Trip ID: `{t['id']}` &nbsp;|&nbsp; 📍 **{t['destination']}**")
                st.markdown(f"**{comp}** of {tot} Complete &nbsp;•&nbsp; :red[{miss} Action Required] &nbsp;•&nbsp; :orange[{att} Pending Review]")
            with c_action:
                st.markdown(f"{render_badge(b_status)}", unsafe_allow_html=True)
                st.write("")
                if st.button("Open Trip", key=f"open_trip_home_{t['id']}", use_container_width=True):
                    st.query_params.trip_id = t['id']
                    st.session_state['nav_page'] = "trip_workspace"
                    st.query_params.page = "trip_workspace"
                    st.rerun()

# 6. Attention Items
st.markdown('<div class="kt-section-title">⚠️ Attention Items</div>', unsafe_allow_html=True)

docs = get_all_documents_for_review()
if docs:
    for d in docs:
        with st.container():
            c1, c2, c3, c4 = st.columns([3, 3, 2, 2])
            with c1:
                st.markdown(f"**{d['customer_name']}**<br><span style='font-size:0.82rem; color:#64748B;'>{d['trip_name']}</span>", unsafe_allow_html=True)
            with c2:
                trav = f" ({d['traveller_name']})" if d.get('traveller_name') else ""
                st.markdown(f"**{d['req_name']}**{trav}<br><span style='font-size:0.82rem; color:#64748B;'>Doc ID: <code>{d['id']}</code></span>", unsafe_allow_html=True)
            with c3:
                st.markdown(f"<div style='padding-top:4px;'>{render_badge(d['status'])}</div>", unsafe_allow_html=True)
            with c4:
                if st.button("Review", key=f"rev_home_{d['id']}", use_container_width=True):
                    st.query_params.doc_id = d['id']
                    st.session_state['nav_page'] = "document_review"
                    st.query_params.page = "document_review"
                    st.rerun()
            st.markdown("<hr style='margin:8px 0; border:none; border-top:1px solid #E5EAF1;'>", unsafe_allow_html=True)
else:
    with st.container(border=True):
        st.markdown(
            "<div style='text-align:center; padding:16px;'>"
            "<span style='font-size:1.8rem; color:#16A34A;'>✓</span>"
            "<div style='font-weight:600; color:#0B2348; margin-top:6px;'>All caught up!</div>"
            "<div style='font-size:0.85rem; color:#64748B;'>No travel documents currently require staff attention.</div>"
            "</div>",
            unsafe_allow_html=True
        )


# 7. Administrator Governance & Deletion Requests (Admin Only)
session_token = st.session_state.get('session_token')
if session_token:
    import auth_services
    current_user = auth_services.get_user_by_token(session_token)
    if current_user and current_user.get('role') in ('Admin', 'Administrator'):
        st.markdown('<div class="kt-section-title">🛡️ Admin Governance & Audit Integrity</div>', unsafe_allow_html=True)
        with st.container(border=True):
            g_col1, g_col2 = st.columns(2)
            with g_col1:
                st.markdown("**Tamper-Evident Audit Log Verification**")
                if st.button("Verify Cryptographic Audit Hash Chain", key="btn_verify_audit_hashes"):
                    valid, count, err = auth_services.verify_audit_log_integrity()
                    if valid:
                        st.success(f"Audit log integrity verified: {count} chained events intact.")
                    else:
                        st.error(f"Audit log verification failed: {err}")
            with g_col2:
                st.markdown("**System Backup Verification Status**")
                b_ok, b_path = services.check_verified_backup_exists()
                if b_ok:
                    st.success("Verified database backup present and validated.")
                else:
                    st.warning("No verified database backup found. Permanent delete blocked.")

            # Pending Deletion Requests
            st.markdown("---")
            st.markdown("**Pending Deletion Requests**")
            try:
                del_requests = services.get_deletion_requests(status="PENDING", session_token=session_token)
                if del_requests:
                    for dr in del_requests:
                        with st.container():
                            r1, r2, r3 = st.columns([3, 4, 3])
                            with r1:
                                st.markdown(f"**{dr['object_type']}**: <code>{dr['object_id']}</code><br><small>By: {dr['requested_by']} ({dr['requested_by_role']})</small>", unsafe_allow_html=True)
                            with r2:
                                st.markdown(f"<small>Reason: {dr['reason']}<br>Date: {dr['requested_at'][:19]}</small>", unsafe_allow_html=True)
                            with r3:
                                note = st.text_input("Review Note", key=f"dr_note_{dr['id']}", placeholder="Review note")
                                b_app, b_rej = st.columns(2)
                                with b_app:
                                    if st.button("Approve", key=f"dr_app_{dr['id']}", use_container_width=True):
                                        services.review_deletion_request(dr['id'], "APPROVED", note, session_token)
                                        st.success("Approved")
                                        st.rerun()
                                with b_rej:
                                    if st.button("Reject", key=f"dr_rej_{dr['id']}", use_container_width=True):
                                        services.review_deletion_request(dr['id'], "REJECTED", note, session_token)
                                        st.info("Rejected")
                                        st.rerun()
                else:
                    st.caption("No pending deletion requests.")
            except Exception as e:
                st.caption(f"Could not load deletion requests: {e}")

            # Multi-Factor Authentication (MFA) Management & Account Recovery
            st.markdown("---")
            st.markdown("**User Multi-Factor Authentication (MFA) Management & Recovery**")
            try:
                conn_mfa = database.get_connection()
                all_users = conn_mfa.execute(
                    "SELECT id, username, full_name, role, COALESCE(is_active, 1) as is_active, COALESCE(mfa_enabled, 0) as mfa_enabled, mfa_enrolled_at, mfa_recovery_hashes, mfa_locked_until FROM users ORDER BY username"
                ).fetchall()
                conn_mfa.close()

                if all_users:
                    for u in all_users:
                        m1, m2, m3, m4 = st.columns([3, 2.5, 2.5, 2])
                        with m1:
                            st.markdown(f"**{u['full_name']}** (<code>{u['username']}</code>)<br><small>Role: {u['role']}</small>", unsafe_allow_html=True)
                        with m2:
                            if u['mfa_enabled']:
                                st.markdown("<span style='color:#16A34A; font-weight:600;'>✅ Enrolled</span>", unsafe_allow_html=True)
                                if u['mfa_enrolled_at']:
                                    st.caption(f"Since: {u['mfa_enrolled_at'][:10]}")
                            else:
                                st.markdown("<span style='color:#D97706; font-weight:600;'>⏳ Pending Setup</span>", unsafe_allow_html=True)
                        with m3:
                            if u['mfa_locked_until']:
                                st.markdown("<span style='color:#DC2626;'>🔒 Locked</span>", unsafe_allow_html=True)
                            else:
                                st.markdown("<span style='color:#16A34A;'>Active</span>", unsafe_allow_html=True)
                        with m4:
                            if u['mfa_enabled'] or u['mfa_locked_until']:
                                if st.button("Reset MFA", key=f"btn_reset_mfa_{u['id']}", help="Revokes sessions and resets MFA for this user"):
                                    auth_services.admin_reset_user_mfa(session_token, u['id'], reason="Admin reset via staff_home")
                                    st.success(f"MFA reset for {u['username']}.")
                                    st.rerun()
                            else:
                                st.caption("No action needed")
            except Exception as e:
                st.caption(f"Could not load MFA user status: {e}")

            # Emergency Recovery Code Rotation (Current Authenticated User Only)
            st.markdown("---")
            st.markdown("**Emergency Recovery Code Rotation (Your Account Only)**")
            st.caption(
                "If your emergency recovery codes were exposed or lost, rotate and replace all 8 codes here. "
                "This requires step-up verification using the current 6-digit code from your Authenticator app. "
                "All 8 prior recovery codes will be immediately and permanently invalidated."
            )

            if "new_rotated_recovery_codes" in st.session_state:
                st.error("⚠️ **CRITICAL: Save Your New Recovery Codes Immediately**")
                st.warning(
                    "These 8 single-use recovery codes have replaced all previous codes. "
                    "They are displayed **once** and cannot be retrieved again after closing or refreshing this notice."
                )
                rec_cols = st.columns(2)
                for idx, c in enumerate(st.session_state["new_rotated_recovery_codes"]):
                    with rec_cols[idx % 2]:
                        st.code(c, language=None)

                if st.button("✓ I Have Safely Stored My New Recovery Codes — Dismiss", key="btn_dismiss_rotated_codes", type="primary"):
                    st.session_state.pop("new_rotated_recovery_codes", None)
                    st.rerun()
            else:
                with st.expander("Rotate Emergency Recovery Codes", expanded=False):
                    st.markdown(
                        "Open **Microsoft Authenticator** on your phone, find **Khanna Travels Vault**, "
                        "and enter the current 6-digit one-time code to authorize rotation:"
                    )
                    rot_c1, rot_c2 = st.columns([2, 2])
                    with rot_c1:
                        step_up_otp = st.text_input(
                            "6-Digit Authenticator Code",
                            max_chars=6,
                            key="step_up_totp_code_input",
                            placeholder="123456",
                            help="Current 6-digit code from Microsoft Authenticator"
                        )
                    with rot_c2:
                        st.write("")
                        st.write("")
                        if st.button("Rotate & Replace All 8 Codes", key="btn_rotate_recovery_codes", type="secondary"):
                            if not step_up_otp or len(step_up_otp.strip()) != 6:
                                st.error("Please enter a valid 6-digit code from your authenticator app.")
                            else:
                                try:
                                    rotated_codes = auth_services.rotate_user_recovery_codes(
                                        session_token=session_token,
                                        totp_code=step_up_otp.strip()
                                    )
                                    st.session_state["new_rotated_recovery_codes"] = rotated_codes
                                    st.success("Recovery codes rotated successfully.")
                                    st.rerun()
                                except Exception as ex:
                                    st.error(f"Rotation failed: {ex}")

