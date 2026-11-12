import streamlit as st
from ui_helpers import inject_custom_css, render_top_nav, render_badge
import services
import base64

inject_custom_css()
render_top_nav()

session_token = st.session_state.get('session_token')
if not session_token:
    st.error("Your session has expired or you are unauthenticated. Please sign in again.")
    st.stop()

st.markdown('<h1 style="color:#0B2348; margin:0; font-size:2rem; font-weight:800;">Advanced Vault Search</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#64748B; margin:4px 0 16px 0; font-size:0.95rem;">Search across customers, travellers, trips, documents, and verified passports with secure preview and download.</p>', unsafe_allow_html=True)

# Search Bar
search_query = st.text_input(
    "Search",
    placeholder="Search customer, traveller, trip, destination, or passport number (e.g. Amit Mehta, Dubai, DEMO-PASSPORT-0001)...",
    key="vault_search_main_query"
).strip()

# Filters Expander
with st.expander("Filter Options", expanded=False):
    f_col1, f_col2, f_col3 = st.columns(3)
    with f_col1:
        doc_type_opts = [
            "All",
            "Passport",
            "Visa / Entry Document",
            "Flight Ticket",
            "Hotel Voucher",
            "Travel Insurance",
            "Transfer Voucher",
            "Sightseeing Voucher",
            "Land Voucher",
            "Aadhaar Card",
            "PAN Card",
            "Arrival / Entry Document",
            "Itinerary"
        ]
        selected_doc_type = st.selectbox("Document Type", doc_type_opts, key="vs_doc_type")
    with f_col2:
        status_opts = ["All", "Verified", "Under Review", "Missing", "Needs Attention", "Re-upload Required"]
        selected_status = st.selectbox("Verification Status", status_opts, key="vs_status")
    with f_col3:
        dest_filter = st.text_input("Destination", placeholder="e.g. Dubai, Singapore", key="vs_dest").strip()

    st.markdown("##### Trip Date Filter")
    date_cols = st.columns([1, 2, 2])
    with date_cols[0]:
        use_date_filter = st.checkbox("Filter by Trip Dates", key="vs_use_dates")
    with date_cols[1]:
        start_date_val = st.date_input("Departure On or After", key="vs_start_date", disabled=not use_date_filter)
    with date_cols[2]:
        end_date_val = st.date_input("Return On or Before", key="vs_end_date", disabled=not use_date_filter)

btn_c1, btn_c2, _ = st.columns([1, 1, 4])
with btn_c1:
    search_clicked = st.button("Search", type="primary", use_container_width=True)
with btn_c2:
    if st.button("Clear Filters", use_container_width=True):
        st.session_state['vault_search_main_query'] = ""
        st.session_state['vs_doc_type'] = "All"
        st.session_state['vs_status'] = "All"
        st.session_state['vs_dest'] = ""
        st.session_state['vs_use_dates'] = False
        st.rerun()

st.markdown("<hr style='margin: 15px 0;'>", unsafe_allow_html=True)

# Prepare search parameters
filter_doc_type = selected_doc_type if selected_doc_type != "All" else None
filter_status = selected_status if selected_status != "All" else None
filter_dest = dest_filter if dest_filter else None
filter_start = start_date_val.strftime("%Y-%m-%d") if use_date_filter and start_date_val else None
filter_end = end_date_val.strftime("%Y-%m-%d") if use_date_filter and end_date_val else None

try:
    results = services.advanced_vault_search(
        session_token=session_token,
        query=search_query if search_query else None,
        document_type=filter_doc_type,
        verification_status=filter_status,
        destination=filter_dest,
        trip_start=filter_start,
        trip_end=filter_end,
        limit=50,
        offset=0
    )
except ValueError as ve:
    st.error(f"Search parameter error: {ve}")
    st.stop()
except PermissionError as pe:
    st.error(f"Access error: {pe}")
    st.stop()
except Exception as e:
    st.error(f"An unexpected search error occurred: {e}")
    st.stop()

docs = results.get('documents', [])
customers = results.get('customers', [])
travellers = results.get('travellers', [])
trips = results.get('trips', [])
total_docs = results.get('total_documents', len(docs))

tab_labels = [
    f"Documents ({total_docs})",
    f"Customers ({len(customers)})",
    f"Travellers ({len(travellers)})",
    f"Trips ({len(trips)})"
]

tabs = st.tabs(tab_labels)

# -------------------------------------------------------------
# TAB 1: DOCUMENTS
# -------------------------------------------------------------
with tabs[0]:
    if not docs:
        st.info("No matching documents found. Try changing your filters.")
    else:
        st.caption(f"Showing {len(docs)} of {total_docs} matching documents")
        for d in docs:
            doc_id = d['doc_id']
            cust_id = d['customer_id']
            trip_id = d.get('trip_id')
            icon = "📄" if d.get('file_format') == "PDF" else "🖼️"
            dest_info = f" ({d['trip_destination']})" if d.get('trip_destination') else ""
            pass_info = f" &nbsp;|&nbsp; Passport: <strong>{d['masked_passport']}</strong>" if d.get('masked_passport') else ""
            
            with st.container(border=True):
                c_top1, c_top2 = st.columns([4, 1.5])
                with c_top1:
                    st.markdown(f"#### {icon} {d['req_name']}")
                with c_top2:
                    st.markdown(f"{render_badge(d['status'])}", unsafe_allow_html=True)
                
                st.markdown(f"**Customer:** {d['customer_name']} (`{cust_id}`) &nbsp;•&nbsp; **Traveller:** {d['traveller_name'] or 'General Trip Requirement'} &nbsp;•&nbsp; **Trip:** {d['trip_name']}{dest_info}")
                st.caption(f"Format: {d.get('file_format', 'UNKNOWN')} &nbsp;|&nbsp; Size: {d.get('file_size_str', '0 KB')} &nbsp;|&nbsp; Uploaded: {d.get('uploaded_at') or 'Unknown'}{pass_info}")

                act_cols = st.columns([1.5, 1.5, 1.5, 1.5, 4])
                
                with act_cols[0]:
                    if st.button("Open Customer", key=f"vs_opencust_{doc_id}", use_container_width=True):
                        st.query_params.customer_id = cust_id
                        st.session_state['nav_page'] = "customer_workspace"
                        st.query_params.page = "customer_workspace"
                        st.rerun()

                with act_cols[1]:
                    if trip_id:
                        if st.button("Open Trip", key=f"vs_opentrip_{doc_id}", use_container_width=True):
                            st.query_params.trip_id = trip_id
                            st.session_state['nav_page'] = "trip_workspace"
                            st.query_params.page = "trip_workspace"
                            st.rerun()
                    else:
                        st.button("Open Trip", key=f"vs_notrip_{doc_id}", disabled=True, use_container_width=True)

                preview_key = f"vs_preview_active_{doc_id}"
                with act_cols[2]:
                    if not d.get('file_exists'):
                        st.button("Preview", key=f"vs_btn_prev_{doc_id}", disabled=True, use_container_width=True)
                    else:
                        if st.button("Preview", key=f"vs_btn_prev_{doc_id}", use_container_width=True):
                            st.session_state[preview_key] = not st.session_state.get(preview_key, False)
                            st.rerun()

                with act_cols[3]:
                    if not d.get('file_exists'):
                        st.button("Download", key=f"vs_btn_dl_na_{doc_id}", disabled=True, use_container_width=True)
                    else:
                        try:
                            dl_data = services.get_document_for_download_or_preview(
                                doc_id=doc_id,
                                customer_id=cust_id,
                                session_token=session_token,
                                action='download'
                            )
                            st.download_button(
                                label="Download",
                                data=dl_data['file_bytes'],
                                file_name=dl_data['file_name'],
                                mime=dl_data['mime_type'],
                                key=f"vs_dl_{doc_id}",
                                use_container_width=True
                            )
                        except Exception as dl_err:
                            st.error(f"Download unavailable: {dl_err}")

                # Inline Preview Area
                if st.session_state.get(preview_key, False):
                    st.markdown("---")
                    prev_c1, prev_c2 = st.columns([5, 1])
                    with prev_c1:
                        st.markdown(f"#### Preview: {d['req_name']} ({d['customer_name']})")
                    with prev_c2:
                        if st.button("Close Preview", key=f"vs_close_prev_{doc_id}", use_container_width=True):
                            st.session_state[preview_key] = False
                            st.rerun()

                    try:
                        p_res = services.get_document_for_download_or_preview(
                            doc_id=doc_id,
                            customer_id=cust_id,
                            session_token=session_token,
                            action='preview'
                        )
                        if p_res['mime_type'] == 'application/pdf':
                            b64_pdf = base64.b64encode(p_res['file_bytes']).decode('utf-8')
                            pdf_display = f'<iframe src="data:application/pdf;base64,{b64_pdf}" width="100%" height="650" style="border: 1px solid #ccc; border-radius: 8px;"></iframe>'
                            st.markdown(pdf_display, unsafe_allow_html=True)
                        elif p_res['mime_type'].startswith('image/'):
                            st.image(p_res['file_bytes'], caption=f"{d['req_name']} - {d['customer_name']}", use_container_width=True)
                        else:
                            st.info("Preview not supported for this format. Please use Download.")
                    except Exception as p_err:
                        st.error(f"Unable to render preview: {p_err}")
                    st.markdown("---")

                st.markdown("<div style='margin-bottom:8px;'></div>", unsafe_allow_html=True)

# -------------------------------------------------------------
# TAB 2: CUSTOMERS
# -------------------------------------------------------------
with tabs[1]:
    if not customers:
        if search_query:
            st.info(f"No customers found matching '{search_query}'.")
        else:
            st.info("No customer search term entered.")
    else:
        for c in customers:
            with st.container(border=True):
                c_top1, c_top2 = st.columns([4, 2])
                with c_top1:
                    st.markdown(f"#### 👤 {c['name']} `({c['id']})`")
                    st.markdown(f"Type: **{c.get('customer_type', 'Individual')}** &nbsp;•&nbsp; Mobile: **{c.get('mobile') or 'N/A'}** &nbsp;•&nbsp; Email: **{c.get('email') or 'N/A'}**")
                with c_top2:
                    st.markdown(f"{render_badge(c.get('status', 'Active'))}", unsafe_allow_html=True)
                    st.write("")
                    if st.button("Open Customer Workspace", key=f"vs_tab_opencust_{c['id']}", use_container_width=True):
                        st.query_params.customer_id = c['id']
                        st.session_state['nav_page'] = "customer_workspace"
                        st.query_params.page = "customer_workspace"
                        st.rerun()

# -------------------------------------------------------------
# TAB 3: TRAVELLERS
# -------------------------------------------------------------
with tabs[2]:
    if not travellers:
        if search_query:
            st.info(f"No travellers found matching '{search_query}'.")
        else:
            st.info("No traveller search query entered.")
    else:
        for tr in travellers:
            with st.container(border=True):
                c_top1, c_top2 = st.columns([4, 2])
                with c_top1:
                    st.markdown(f"#### 👤 {tr['name']} `({tr['id']})`")
                    pass_str = f"Passport: `{tr['masked_passport']}`" if tr.get('masked_passport') else "Passport: *Not on file*"
                    st.markdown(f"Customer: **{tr['customer_name']}** (`{tr['customer_id']}`) &nbsp;•&nbsp; Type: **{tr.get('type', 'Adult')}** &nbsp;•&nbsp; {pass_str}")
                with c_top2:
                    st.write("")
                    if st.button("Open Customer", key=f"vs_tab_opentrav_{tr['id']}", use_container_width=True):
                        st.query_params.customer_id = tr['customer_id']
                        st.session_state['nav_page'] = "customer_workspace"
                        st.query_params.page = "customer_workspace"
                        st.rerun()

# -------------------------------------------------------------
# TAB 4: TRIPS
# -------------------------------------------------------------
with tabs[3]:
    if not trips:
        if search_query or filter_dest or filter_start:
            st.info("No trips found matching your search criteria.")
        else:
            st.info("No trip filters applied.")
    else:
        for trip in trips:
            with st.container(border=True):
                c_top1, c_top2 = st.columns([4, 2])
                with c_top1:
                    st.markdown(f"#### ✈️ {trip['name']} `({trip['id']})`")
                    st.markdown(f"Customer: **{trip['customer_name']}** (`{trip['customer_id']}`) &nbsp;•&nbsp; 📍 **{trip['destination']}** &nbsp;•&nbsp; 📅 {trip['start_date']} to {trip['end_date']}")
                with c_top2:
                    st.markdown(f"{render_badge(trip.get('status', 'Planning'))}", unsafe_allow_html=True)
                    st.write("")
                    if st.button("Open Trip Workspace", key=f"vs_tab_opentrip_{trip['id']}", use_container_width=True):
                        st.query_params.trip_id = trip['id']
                        st.session_state['nav_page'] = "trip_workspace"
                        st.query_params.page = "trip_workspace"
                        st.rerun()
