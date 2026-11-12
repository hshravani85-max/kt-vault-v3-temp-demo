import streamlit as st
from ui_helpers import inject_custom_css, render_top_nav, render_badge
import database

inject_custom_css()
render_top_nav()

# Header
head_col, btn_col = st.columns([4, 1.5])
with head_col:
    st.markdown('<h1 style="color:#0B2348; margin:0; font-size:2rem; font-weight:800;">Documents</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:#64748B; margin:4px 0 16px 0; font-size:0.95rem;">Master vault of all customer documents, trip vouchers, and identity records.</p>', unsafe_allow_html=True)
with btn_col:
    if st.button("📤 Smart Upload", type="primary", use_container_width=True, icon=":material/upload_file:"):
        if 'upload_req_id' in st.session_state:
            del st.session_state['upload_req_id']
        if 'upload_trip_id' in st.session_state:
            del st.session_state['upload_trip_id']
        st.session_state['nav_page'] = "smart_upload"
        st.query_params.page = "smart_upload"
        st.rerun()

# Filter Controls
f_col1, f_col2 = st.columns([3, 2])
with f_col1:
    search_doc = st.text_input("Search Documents", placeholder="e.g. Passport, Neha, Dubai...", key="doc_search_input").strip().lower()
with f_col2:
    status_filter = st.selectbox(
        "Status Filter",
        ["All Documents", "Under Review", "Verified", "Re-upload Required", "Needs Attention"],
        key="doc_status_filter"
    )

conn = database.get_connection()
docs = conn.execute('''
    SELECT d.*, r.name as req_name, r.type as req_type, 
           COALESCE(c.name, c2.name) as customer_name, 
           t.name as trip_name, tr.name as traveller_name
    FROM documents d
    JOIN requirements r ON d.requirement_id = r.id
    LEFT JOIN trips t ON r.trip_id = t.id
    LEFT JOIN customers c ON t.customer_id = c.id
    LEFT JOIN travellers tr ON r.traveller_id = tr.id
    LEFT JOIN customers c2 ON tr.customer_id = c2.id
    ORDER BY d.uploaded_at DESC
''').fetchall()
conn.close()

docs = [dict(d) for d in docs]

if status_filter != "All Documents":
    docs = [d for d in docs if d['status'] == status_filter]

if search_doc:
    docs = [d for d in docs if search_doc in (d['customer_name'] or '').lower() or search_doc in (d['req_name'] or '').lower() or search_doc in (d['trip_name'] or '').lower() or search_doc in (d['traveller_name'] or '').lower() or search_doc in d['id'].lower()]

if not docs:
    st.info("No documents match your filter criteria.")
else:
    st.markdown(f"<div style='font-size:0.85rem; color:#64748B; margin-bottom:12px;'>Showing <strong>{len(docs)}</strong> travel documents</div>", unsafe_allow_html=True)
    for d in docs:
        with st.container():
            c1, c2, c3, c4, c5 = st.columns([3, 3, 2, 2, 1.5])
            with c1:
                st.markdown(f"**{d['customer_name']}**<br><span style='font-size:0.82rem; color:#64748B;'>{d['trip_name'] or 'Traveller Vault (Reusable)'}</span>", unsafe_allow_html=True)
            with c2:
                trav = f"<br><span style='font-size:0.82rem; color:#64748B;'>👤 {d['traveller_name']}</span>" if d['traveller_name'] else "<br><span style='font-size:0.82rem; color:#64748B;'>Trip Level</span>"
                st.markdown(f"**{d['req_name']}**{trav}", unsafe_allow_html=True)
            with c3:
                st.markdown(f"<div style='padding-top:4px;'>{render_badge(d['status'])}</div>", unsafe_allow_html=True)
            with c4:
                up_dt = d['uploaded_at'][:10] if d.get('uploaded_at') else ''
                st.markdown(f"<span style='font-size:0.85rem; color:#64748B;'>📅 {up_dt}</span><br><code style='font-size:0.78rem;'>{d['id']}</code>", unsafe_allow_html=True)
            with c5:
                if d['status'] == 'Under Review':
                    if st.button("Review", key=f"rev_doc_{d['id']}", use_container_width=True):
                        st.query_params.doc_id = d['id']
                        st.session_state['nav_page'] = "document_review"
                        st.query_params.page = "document_review"
                        st.rerun()
                else:
                    if st.button("View", key=f"view_doc_{d['id']}", use_container_width=True):
                        st.query_params.doc_id = d['id']
                        st.session_state['nav_page'] = "document_review"
                        st.query_params.page = "document_review"
                        st.rerun()
            st.markdown("<hr style='margin:10px 0; border:none; border-top:1px solid #E5EAF1;'>", unsafe_allow_html=True)
