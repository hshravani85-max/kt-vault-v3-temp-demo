import streamlit as st
from ui_helpers import inject_custom_css, render_top_nav, render_badge
import database
import services
import auth_services

inject_custom_css()
render_top_nav()

# Page Header
head_col, btn_col1, btn_col2 = st.columns([3, 1.5, 1.5])
with head_col:
    st.markdown('<h1 style="color:#0B2348; margin:0; font-size:2rem; font-weight:800;">Customers</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:#64748B; margin:4px 0 16px 0; font-size:0.95rem;">Manage customer accounts, traveller profiles, and document vaults.</p>', unsafe_allow_html=True)
with btn_col1:
    if st.button("➕ New from Document", type="primary", use_container_width=True, icon=":material/person_add:"):
        st.session_state['nav_page'] = "smart_intake"
        st.query_params.page = "smart_intake"
        st.rerun()
with btn_col2:
    if st.button("➕ Add Manually", use_container_width=True, icon=":material/edit:"):
        st.session_state['show_add_customer'] = True

if st.session_state.get('show_add_customer', False):
    st.markdown('<div class="kt-card">', unsafe_allow_html=True)
    st.markdown("### Create New Customer")
    with st.form("add_customer_form"):
        name = st.text_input("Full Name *")
        mobile = st.text_input("Mobile Number")
        email = st.text_input("Email Address")
        ctype = st.selectbox("Customer Type", ["Individual", "Family", "Corporate", "Group"])
        
        col1, col2 = st.columns(2)
        with col1:
            submit = st.form_submit_button("Save Customer", type="primary")
        with col2:
            cancel = st.form_submit_button("Cancel")
            
        if submit:
            if not name.strip():
                st.error("Full Name is required.")
            else:
                new_id = services.create_customer(
                    full_name=name.strip(),
                    mobile=mobile.strip() if mobile.strip() else None,
                    email=email.strip() if email.strip() else None,
                    customer_type=ctype,
                    session_token=st.session_state.get('session_token')
                )
                st.session_state['show_add_customer'] = False
                st.query_params.customer_id = new_id
                st.session_state['nav_page'] = "customer_workspace"
                st.query_params.page = "customer_workspace"
                st.rerun()
        if cancel:
            st.session_state['show_add_customer'] = False
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

col_s1, col_s2, col_s3 = st.columns([2.3, 1.5, 0.9])
with col_s1:
    search_term = st.text_input("Search Customer (Name, ID, Mobile, Email)", placeholder="e.g. Amit Mehta or KT-C-0001", key="customer_search_term").strip()
with col_s2:
    compliance_filter = st.selectbox(
        "Mandatory Compliance Filter",
        ["All Customers", "Missing Either Document", "Missing Aadhaar", "Missing PAN", "Pending Verification", "Rejected", "Fully Complete (2/2)"],
        key="compliance_filter_select"
    )
with col_s3:
    st.write("")
    st.write("")
    show_archived = st.checkbox("Show Archived", value=False, key="show_archived_customers")

session_token = st.session_state.get('session_token')
if search_term:
    try:
        customers = services.search_customers(search_term, session_token, include_archived=show_archived)
    except Exception as e:
        st.error(f"Search error: {e}")
        customers = []
else:
    conn = database.get_connection()
    archived_val = 1 if show_archived else 0
    customers = conn.execute("SELECT * FROM customers WHERE (archived = 0 OR ? = 1) ORDER BY id DESC", (archived_val,)).fetchall()
    conn.close()
    customers = [dict(c) for c in customers]

# Filter by mandatory compliance if selected
if compliance_filter != "All Customers":
    filtered_by_comp = []
    for c in customers:
        m_stat = services.get_customer_mandatory_status(c['id'])
        a_doc = next((d for d in m_stat['documents'] if d['name'] == 'Aadhaar Card'), None)
        p_doc = next((d for d in m_stat['documents'] if d['name'] == 'PAN Card'), None)
        a_s = a_doc['status'] if a_doc else 'Missing'
        p_s = p_doc['status'] if p_doc else 'Missing'

        if compliance_filter == "Fully Complete (2/2)" and m_stat['is_complete']:
            filtered_by_comp.append(c)
        elif compliance_filter == "Missing Either Document" and (a_s == 'Missing' or p_s == 'Missing'):
            filtered_by_comp.append(c)
        elif compliance_filter == "Missing Aadhaar" and a_s == 'Missing':
            filtered_by_comp.append(c)
        elif compliance_filter == "Missing PAN" and p_s == 'Missing':
            filtered_by_comp.append(c)
        elif compliance_filter == "Pending Verification" and (a_s == 'Pending Verification' or p_s == 'Pending Verification'):
            filtered_by_comp.append(c)
        elif compliance_filter == "Rejected" and (a_s == 'Rejected' or p_s == 'Rejected'):
            filtered_by_comp.append(c)
    customers = filtered_by_comp

if not customers:
    if search_term:
        st.info(f"No customers found matching '{search_term}'.")
    else:
        st.info("No customers found.")
else:
    st.markdown(f"<div style='font-size:0.85rem; color:#64748B; margin-bottom:12px;'>Showing <strong>{len(customers)}</strong> customer accounts</div>", unsafe_allow_html=True)
    for c in customers:
        with st.container():
            c1, c2, c3, c4 = st.columns([2, 4, 2, 2])
            with c1:
                st.markdown(f"**<code>{c['id']}</code>**", unsafe_allow_html=True)
            with c2:
                contact_info = []
                if c.get('mobile'): contact_info.append(f"📞 {c['mobile']}")
                if c.get('email'): contact_info.append(f"✉️ {c['email']}")
                contact_str = f"<span style='font-size:0.8rem; color:#64748B;'>{' • '.join(contact_info)}</span>" if contact_info else ""
                st.markdown(f"<div style='font-weight:700; font-size:1.05rem; color:#0B2348;'>{c['name']}</div>{contact_str}", unsafe_allow_html=True)
            with c3:
                m_info = services.get_customer_mandatory_status(c['id'])
                c_color = "#10B981" if m_info['is_complete'] else ("#F59E0B" if m_info['progress_percent'] > 0 else "#EF4444")
                m_badge = f"<div style='margin-top:4px;'><span style='font-size:0.75rem; font-weight:700; color:{c_color}; background:#F8FAFC; border:1px solid {c_color}; border-radius:10px; padding:2px 7px;'>ID: {m_info['completion_ratio']} Verified</span></div>"
                st.markdown(f"<div style='margin-bottom:4px;'><span style='font-size:0.82rem; color:#64748B; font-weight:600;'>{c['customer_type']}</span></div>{render_badge(c['status'])}{m_badge}", unsafe_allow_html=True)
            with c4:
                if st.button("Open Workspace", key=f"open_cust_{c['id']}", use_container_width=True):
                    st.query_params.customer_id = c['id']
                    st.session_state['nav_page'] = "customer_workspace"
                    st.query_params.page = "customer_workspace"
                    st.rerun()

                # Archive / Unarchive / Deletion Actions
                current_user = auth_services.get_user_by_token(session_token) if session_token else None
                is_admin = current_user and current_user.get('role') in ('Admin', 'Administrator')

                is_archived = c.get('archived', 0) == 1
                if is_archived:
                    st.markdown("<span style='font-size:0.75rem; font-weight:700; color:#475569; background:#E2E8F0; border-radius:8px; padding:2px 8px;'>ARCHIVED</span>", unsafe_allow_html=True)
                    if is_admin:
                        if st.button("Restore to Active List", key=f"unarch_cust_{c['id']}", use_container_width=True):
                            try:
                                services.unarchive_customer(c['id'], session_token)
                                st.success(f"Customer '{c['id']}' restored to active view.")
                                st.rerun()
                            except Exception as ex:
                                st.error(f"Error restoring customer: {ex}")
                else:
                    if is_admin:
                        with st.expander("Actions", expanded=False):
                            # 1. Archive Customer (Admin-only)
                            st.markdown("**Archive Customer**")
                            st.caption("Hides customer from active list. All trips, documents, and records are preserved.")
                            arch_reason = st.text_input("Archive Reason", key=f"arch_reason_{c['id']}", placeholder="e.g. Duplicate account, closed").strip()
                            if st.button("Archive Customer", key=f"btn_arch_{c['id']}", use_container_width=True):
                                if len(arch_reason) < 3:
                                    st.warning("Please enter a reason (min 3 characters).")
                                else:
                                    try:
                                        services.archive_customer(c['id'], arch_reason, session_token)
                                        st.success(f"Customer '{c['id']}' archived.")
                                        st.rerun()
                                    except Exception as ex:
                                        st.error(f"Error archiving: {ex}")

                            st.markdown("---")
                            # 2. Delete Customer (with Dependency Safety Check)
                            st.markdown("**Delete Customer**")
                            safety = services.check_customer_deletion_safety(c['id'], session_token)
                            if not safety["can_delete"]:
                                conflict_list = ", ".join(safety["conflicts"])
                                st.warning(f"⚠️ **Deletion Blocked:** Customer has linked records ({conflict_list}). Cascade deletion is strictly forbidden to protect data integrity. Please use **Archive Customer** above instead.")
                            else:
                                st.caption("This customer has no linked trips, travellers, or documents. It can be safely removed.")
                                del_confirm = st.text_input(f"Type '{c['id']}' to confirm", key=f"del_confirm_{c['id']}", placeholder=c['id']).strip()
                                del_reason = st.text_input("Deletion Reason", key=f"safe_del_reason_{c['id']}", placeholder="e.g. Empty duplicate record").strip()
                                if st.button("Delete Customer Permanently", key=f"btn_safe_del_{c['id']}", type="secondary", use_container_width=True):
                                    if del_confirm != c['id']:
                                        st.error(f"Confirmation mismatch. Please type exact customer ID '{c['id']}'.")
                                    elif len(del_reason) < 3:
                                        st.warning("Please enter a deletion reason (min 3 characters).")
                                    else:
                                        try:
                                            services.safe_delete_customer(c['id'], del_confirm, del_reason, session_token)
                                            st.success(f"Customer '{c['id']}' successfully deleted.")
                                            st.rerun()
                                        except Exception as ex:
                                            st.error(f"Deletion failed: {ex}")
                    else:
                        # Non-admin staff view: preserve Request Deletion workflow
                        with st.expander("Actions", expanded=False):
                            del_req_reason = st.text_input("Deletion Request Reason", key=f"del_req_reason_{c['id']}", placeholder="Reason for Admin review").strip()
                            if st.button("Request Deletion", key=f"btn_del_req_{c['id']}", use_container_width=True):
                                if len(del_req_reason) < 5:
                                    st.warning("Please enter a reason (min 5 characters).")
                                else:
                                    try:
                                        services.create_deletion_request('CUSTOMER', c['id'], del_req_reason, session_token)
                                        st.success("Deletion request submitted for Admin review.")
                                        st.rerun()
                                    except Exception as ex:
                                        st.error(f"Error requesting deletion: {ex}")

            st.markdown("<hr style='margin:10px 0; border:none; border-top:1px solid #E5EAF1;'>", unsafe_allow_html=True)
