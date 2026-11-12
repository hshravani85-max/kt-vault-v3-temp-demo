import streamlit as st
from ui_helpers import inject_custom_css, render_top_nav, render_badge
from services import calculate_readiness
import database

inject_custom_css()
render_top_nav()

# Header
st.markdown('<h1 style="color:#0B2348; margin:0; font-size:2rem; font-weight:800;">Trips</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#64748B; margin:4px 0 16px 0; font-size:0.95rem;">Monitor trip readiness, travel file compliance, and required document checklists.</p>', unsafe_allow_html=True)

search_q = st.text_input("Search Trip (ID, Customer, Destination, Trip Name)", placeholder="e.g. Dubai, Amit Mehta, or KT-T-0001", key="trip_search_input").strip().lower()

conn = database.get_connection()
trips = conn.execute('''
    SELECT t.*, c.name as customer_name
    FROM trips t JOIN customers c ON t.customer_id = c.id
    ORDER BY t.start_date ASC
''').fetchall()
conn.close()

if search_q:
    trips = [t for t in trips if search_q in t['id'].lower() or search_q in (t['name'] or '').lower() or search_q in (t['destination'] or '').lower() or search_q in (t['customer_name'] or '').lower()]

if not trips:
    st.info("No trips found matching your search criteria.")
else:
    st.markdown(f"<div style='font-size:0.85rem; color:#64748B; margin-bottom:12px;'>Showing <strong>{len(trips)}</strong> active trips</div>", unsafe_allow_html=True)
    for t in trips:
        total, comp, att, miss, pct, business_status = calculate_readiness(t['id'])
        dest_icon = "🏰" if "Dubai" in (t['destination'] or '') else ("🌆" if "Singapore" in (t['destination'] or '') else "✈️")
        
        with st.container(border=True):
            c_icon, c_info, c_ready, c_btn = st.columns([0.8, 4.5, 2.5, 2])
            with c_icon:
                st.markdown(f"<div style='font-size:2rem; text-align:center; padding-top:6px;'>{dest_icon}</div>", unsafe_allow_html=True)
            with c_info:
                st.markdown(f"#### {t['name']} `({t['id']})`")
                st.markdown(f"Customer: **{t['customer_name']}** &nbsp;•&nbsp; 📍 **{t['destination']}**")
                st.caption(f"📅 {t['start_date']} to {t['end_date']} &nbsp;|&nbsp; Service: {t['service']}")
            with c_ready:
                st.markdown(f"**Readiness: {pct}%**")
                st.caption(f"{comp} of {total} Complete ({miss} missing)")
                st.markdown(f"{render_badge(business_status)}", unsafe_allow_html=True)
            with c_btn:
                st.write("")
                if st.button("Open Trip", key=f"open_trip_{t['id']}", use_container_width=True):
                    st.query_params.trip_id = t['id']
                    st.session_state['nav_page'] = "trip_workspace"
                    st.query_params.page = "trip_workspace"
                    st.rerun()
