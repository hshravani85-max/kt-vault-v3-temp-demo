import streamlit as st
import textwrap
import os
import base64

# ==============================================================================
# KHANNA TRAVELS DESIGN SYSTEM - CONSTANTS & TOKENS
# ==============================================================================
__all__ = [
    'COLOR_NAVY', 'COLOR_KHANNA_BLUE', 'COLOR_PAGE_BG', 'COLOR_CARD_BG',
    'COLOR_TEXT_MAIN', 'COLOR_TEXT_MUTED', 'COLOR_BORDER',
    'STATUS_SUCCESS', 'STATUS_WARNING', 'STATUS_DANGER', 'STATUS_INFO',
    'LOGO_PATH', 'get_logo_data_uri', 'render_logo_html',
    'inject_custom_css', 'render_badge', 'render_kpi_card',
    'render_welcome_banner', 'render_sidebar', 'render_top_nav'
]

COLOR_NAVY = "#0B2348"        # Primary brand typography & dark accents
COLOR_KHANNA_BLUE = "#0875B8" # Interactive buttons, active links, brand accents
COLOR_PAGE_BG = "#F7F9FC"     # Clean soft dashboard background
COLOR_CARD_BG = "#FFFFFF"     # Surface white for cards and modals
COLOR_TEXT_MAIN = "#172B4D"   # High contrast readable body text
COLOR_TEXT_MUTED = "#64748B"  # Subtitles, captions, metadata
COLOR_BORDER = "#E5EAF1"      # Subtle clean borders

# Status Tokens
STATUS_SUCCESS = {"color": "#15803D", "bg": "#DCFCE7", "border": "#BBF7D0", "label": "Verified"}
STATUS_WARNING = {"color": "#B45309", "bg": "#FEF3C7", "border": "#FDE68A", "label": "Needs Attention"}
STATUS_DANGER  = {"color": "#B91C1C", "bg": "#FEE2E2", "border": "#FECACA", "label": "Action Required"}
STATUS_INFO    = {"color": "#1D4ED8", "bg": "#DBEAFE", "border": "#BFDBFE", "label": "Under Review"}

LOGO_PATH = os.path.join(os.path.dirname(__file__), "assets", "logo.png")

def get_logo_data_uri():
    """
    Returns base64 data URI of the official Khanna Travels logo if it exists,
    otherwise None.
    """
    if os.path.exists(LOGO_PATH):
        try:
            with open(LOGO_PATH, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("utf-8")
            return f"data:image/png;base64,{b64}"
        except Exception:
            return None
    return None

def render_logo_html(max_width="210px", alt_text="Khanna Travels"):
    """
    Returns an HTML <img> tag for the official logo with preserved aspect ratio,
    or None if the logo asset is not available.
    """
    uri = get_logo_data_uri()
    if not uri:
        return None
    return f'<img src="{uri}" alt="{alt_text}" style="width:100%; max-width:{max_width}; height:auto; display:block; margin:0 auto;" />'


def inject_custom_css():
    """
    Injects enterprise SaaS CSS tokens, typography, and Streamlit component
    customizations according to the approved Khanna Travels design system.
    """
    st.markdown('''
    <style>
        /* Base typography & page canvas */
        html, body, [data-testid="stAppViewContainer"] {
            background-color: #F7F9FC !important;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
            color: #172B4D !important;
        }

        /* Top padding reduction for clean enterprise feel */
        .block-container {
            padding-top: 2rem !important;
            padding-bottom: 3rem !important;
            max-width: 1350px !important;
        }

        /* Standardized Card Container */
        .kt-card {
            background: #FFFFFF;
            border: 1px solid #E5EAF1;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 18px;
            box-shadow: 0 1px 3px rgba(11, 35, 72, 0.04), 0 1px 2px rgba(11, 35, 72, 0.02);
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .kt-card:hover {
            border-color: #CBD5E1;
            box-shadow: 0 4px 6px -1px rgba(11, 35, 72, 0.06), 0 2px 4px -1px rgba(11, 35, 72, 0.04);
        }

        /* Legacy .card compatibility */
        .card {
            background: #FFFFFF;
            border: 1px solid #E5EAF1;
            border-radius: 12px;
            padding: 18px;
            margin-bottom: 16px;
            box-shadow: 0 1px 3px rgba(11, 35, 72, 0.04);
        }

        /* KPI Card Styling */
        .kpi-card-box {
            background: #FFFFFF;
            border: 1px solid #E5EAF1;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 14px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 105px;
            box-shadow: 0 1px 3px rgba(11, 35, 72, 0.03);
            border-top: 4px solid #0875B8;
        }
        .kpi-val {
            font-size: 2rem;
            font-weight: 700;
            line-height: 1.1;
            color: #0B2348;
            margin: 4px 0;
        }
        .kpi-lbl {
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #64748B;
        }

        /* Status Badges */
        .kt-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            border-radius: 16px;
            font-size: 0.78rem;
            font-weight: 600;
            line-height: 1.2;
            white-space: nowrap;
        }
        .kt-badge-success { background-color: #DCFCE7; color: #15803D; border: 1px solid #BBF7D0; }
        .kt-badge-warning { background-color: #FEF3C7; color: #B45309; border: 1px solid #FDE68A; }
        .kt-badge-danger  { background-color: #FEE2E2; color: #B91C1C; border: 1px solid #FECACA; }
        .kt-badge-info    { background-color: #DBEAFE; color: #1D4ED8; border: 1px solid #BFDBFE; }
        .kt-badge-neutral { background-color: #F1F5F9; color: #475569; border: 1px solid #E2E8F0; }

        /* Legacy badge backward-compat */
        .badge {
            padding: 4px 10px; border-radius: 14px; font-size: 0.8rem; font-weight: 600;
        }
        .badge.missing { background-color: #FEE2E2; color: #B91C1C; border: 1px solid #FECACA; }
        .badge.verified { background-color: #DCFCE7; color: #15803D; border: 1px solid #BBF7D0; }
        .badge.attention { background-color: #FEF3C7; color: #B45309; border: 1px solid #FDE68A; }
        .badge.review { background-color: #DBEAFE; color: #1D4ED8; border: 1px solid #BFDBFE; }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: #FFFFFF !important;
            border-right: 1px solid #E5EAF1 !important;
            box-shadow: 1px 0 3px rgba(11, 35, 72, 0.02) !important;
        }
        section[data-testid="stSidebar"] [data-testid="stSidebarContent"] {
            padding-top: 1.5rem !important;
            padding-left: 1.2rem !important;
            padding-right: 1.2rem !important;
        }

        /* Sidebar Brand & Notice */
        .sidebar-brand-box {
            padding: 10px 0 16px 0;
            border-bottom: 1px solid #E5EAF1;
            margin-bottom: 16px;
        }
        .sidebar-brand-title {
            font-size: 1.2rem;
            font-weight: 800;
            color: #0B2348;
            letter-spacing: 0.5px;
            line-height: 1.2;
        }
        .sidebar-brand-sub {
            font-size: 0.75rem;
            font-weight: 600;
            color: #0875B8;
            letter-spacing: 1.2px;
            margin-top: 3px;
        }
        .sidebar-brand-notice {
            font-size: 0.68rem;
            color: #94A3B8;
            background: #F8FAFC;
            border: 1px dashed #CBD5E1;
            border-radius: 6px;
            padding: 4px 6px;
            margin-top: 8px;
            line-height: 1.3;
        }

        /* Sidebar User Profile */
        .sidebar-user-box {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 12px;
            background: #F8FAFC;
            border: 1px solid #E5EAF1;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .sidebar-user-avatar {
            width: 34px;
            height: 34px;
            border-radius: 50%;
            background: #0B2348;
            color: #FFFFFF;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.85rem;
            flex-shrink: 0;
        }
        .sidebar-user-name {
            font-size: 0.88rem;
            font-weight: 600;
            color: #0B2348;
            line-height: 1.2;
        }
        .sidebar-user-role {
            font-size: 0.72rem;
            font-weight: 500;
            color: #64748B;
        }

        /* Sidebar Buttons */
        section[data-testid="stSidebar"] div.stButton > button {
            text-align: left !important;
            justify-content: flex-start !important;
            width: 100% !important;
            border-radius: 8px !important;
            padding: 0.55rem 0.85rem !important;
            font-size: 0.92rem !important;
            font-weight: 500 !important;
            border: 1px solid transparent !important;
            background-color: transparent !important;
            color: #172B4D !important;
            transition: all 0.12s ease-in-out !important;
            margin-bottom: 3px !important;
        }
        section[data-testid="stSidebar"] div.stButton > button:hover {
            background-color: #F1F5F9 !important;
            color: #0875B8 !important;
            border-color: #E2E8F0 !important;
        }
        /* Active Sidebar item (styled via primary) */
        section[data-testid="stSidebar"] div.stButton > button[kind="primary"] {
            background-color: #EBF3FA !important;
            color: #0875B8 !important;
            font-weight: 600 !important;
            border-left: 4px solid #0875B8 !important;
            border-top: 1px solid #D6E4F0 !important;
            border-right: 1px solid #D6E4F0 !important;
            border-bottom: 1px solid #D6E4F0 !important;
        }

        /* Main Canvas Button Styling */
        div.stButton > button:first-child,
        div.stButton > button[kind="primary"] {
            background-color: #0875B8;
            color: #FFFFFF;
            border-radius: 8px;
            border: none;
            padding: 0.5rem 1.1rem;
            font-weight: 600;
            font-size: 0.92rem;
            box-shadow: 0 1px 2px rgba(8, 117, 184, 0.15);
            transition: background-color 0.15s ease;
        }
        div.stButton > button:first-child:hover,
        div.stButton > button[kind="primary"]:hover {
            background-color: #065A8E;
            color: #FFFFFF;
        }
        div.stButton > button[kind="secondary"] {
            background-color: #FFFFFF;
            color: #172B4D;
            border: 1px solid #E5EAF1;
            border-radius: 8px;
            font-weight: 500;
        }
        div.stButton > button[kind="secondary"]:hover {
            background-color: #F8FAFC;
            border-color: #CBD5E1;
            color: #0875B8;
        }

        /* Form Inputs & Controls */
        div[data-baseweb="input"] {
            border-radius: 8px !important;
        }
        div[data-baseweb="select"] {
            border-radius: 8px !important;
        }

        /* Subtle Section Header */
        .kt-section-title {
            font-size: 1.15rem;
            font-weight: 700;
            color: #0B2348;
            margin: 24px 0 14px 0;
            letter-spacing: -0.2px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Quick Action Cards */
        .qa-card {
            background: #FFFFFF;
            border: 1px solid #E5EAF1;
            border-radius: 10px;
            padding: 16px;
            text-align: center;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .qa-card:hover {
            border-color: #0875B8;
            background: #F8FBFE;
        }
    </style>
    ''', unsafe_allow_html=True)


def render_badge(status):
    """
    Renders an accessible, beautifully styled status badge with standard color tokens.
    """
    mapping = {
        'Verified': ('kt-badge-success', '✓ Verified'),
        'Uploaded / Verified': ('kt-badge-success', '✓ Uploaded & Verified'),
        'Pending Verification': ('kt-badge-info', '● Pending Verification'),
        'Complete': ('kt-badge-success', '✓ Complete'),
        'Active': ('kt-badge-success', 'Active'),
        'TRAVEL FILE READY': ('kt-badge-success', '✓ Travel File Ready'),
        'Under Review': ('kt-badge-info', '● Under Review'),
        'Needs Review': ('kt-badge-info', '● Needs Review'),
        'Needs Attention': ('kt-badge-warning', '▲ Needs Attention'),
        'READY FOR FINAL REVIEW': ('kt-badge-warning', '▲ Ready for Final Review'),
        'Missing': ('kt-badge-danger', '✕ Missing'),
        'NOT READY': ('kt-badge-danger', '✕ Not Ready'),
        'Replace Required': ('kt-badge-danger', '✕ Replace Required'),
        'Re-upload Required': ('kt-badge-danger', '✕ Re-upload Required'),
        'Action Required': ('kt-badge-danger', '✕ Action Required'),
        'Rejected': ('kt-badge-danger', '✕ Rejected')
    }
    css_class, text = mapping.get(status, ('kt-badge-neutral', status))
    return f'<span class="kt-badge {css_class}">{text}</span>'


def render_kpi_card(label, value, color="#0875B8", icon=None):
    """
    Renders a clean, structured KPI metric card.
    """
    icon_html = f"<span style='font-size:1.1rem; margin-right:6px;'>{icon}</span>" if icon else ""
    return f'''
    <div class="kpi-card-box" style="border-top-color: {color};">
        <div class="kpi-lbl">{icon_html}{label}</div>
        <div class="kpi-val" style="color: {color if value > 0 else '#64748B'};">{value}</div>
    </div>
    '''


def render_welcome_banner():
    """
    Renders the professional travel photography welcome banner.
    Uses local asset welcome_banner.jpg with dark navy gradient overlay.
    """
    banner_path = os.path.join(os.path.dirname(__file__), "assets", "welcome_banner.jpg")
    img_b64 = ""
    if os.path.exists(banner_path):
        try:
            with open(banner_path, "rb") as f:
                img_b64 = base64.b64encode(f.read()).decode("utf-8")
        except Exception:
            pass

    bg_style = (
        f"background: linear-gradient(135deg, rgba(11, 35, 72, 0.88) 0%, rgba(8, 117, 184, 0.78) 100%), "
        f"url('data:image/jpeg;base64,{img_b64}') center / cover no-repeat;"
        if img_b64 else
        "background: linear-gradient(135deg, #0B2348 0%, #0875B8 100%);"
    )

    st.markdown(textwrap.dedent(f'''
    <div style="{bg_style} border-radius: 14px; padding: 36px 32px; color: white; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(11, 35, 72, 0.12);">
        <div style="font-size: 0.82rem; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: #93C5FD; margin-bottom: 6px;">
            KHANNA TRAVELS
        </div>
        <h1 style="margin: 0; font-size: 2.1rem; font-weight: 800; line-height: 1.2; color: #FFFFFF;">
            Customer Travel Document Vault
        </h1>
        <p style="margin: 12px 0 0 0; font-size: 1.05rem; color: #E0F2FE; font-weight: 400; opacity: 0.95;">
            Organised Documents &nbsp;|&nbsp; Smoother Journeys &nbsp;|&nbsp; Happier Travels
        </p>
    </div>
    '''), unsafe_allow_html=True)




def render_sidebar(active_user, current_page):
    """
    Renders the unified Khanna Travels left-hand sidebar.
    - Brand header with official Khanna Travels logo
    - Staff user profile
    - Full, unclipped navigation links with active state
    - Clean Logout action
    """
    with st.sidebar:
        # Brand Header with Official Logo
        logo_html = render_logo_html(max_width="210px")
        if logo_html:
            st.markdown(textwrap.dedent(f'''
            <div class="sidebar-brand-box" style="background:#FFFFFF; border:1px solid #E5EAF1; border-radius:10px; padding:14px 12px 10px 12px; margin-bottom:16px; text-align:center; box-shadow:0 1px 3px rgba(11,35,72,0.03);">
                {logo_html}
                <div style="font-size:0.68rem; font-weight:700; color:#0875B8; letter-spacing:1.5px; margin-top:8px; text-transform:uppercase;">
                    CUSTOMER VAULT V3
                </div>
            </div>
            '''), unsafe_allow_html=True)
        else:
            st.markdown(textwrap.dedent('''
            <div class="sidebar-brand-box">
                <div class="sidebar-brand-title">KHANNA TRAVELS</div>
                <div class="sidebar-brand-sub">CUSTOMER VAULT V3</div>
                <div class="sidebar-brand-notice">
                    ℹ️ Official logo asset required. Using neutral text placeholder.
                </div>
            </div>
            '''), unsafe_allow_html=True)

        # User Profile
        full_name = active_user.get('full_name', 'Staff Member') if active_user else 'Guest'
        role = active_user.get('role', 'Staff') if active_user else ''
        initials = "".join([part[0] for part in full_name.split()[:2]]).upper() or "KT"

        st.markdown(textwrap.dedent(f'''
        <div class="sidebar-user-box">
            <div class="sidebar-user-avatar">{initials}</div>
            <div>
                <div class="sidebar-user-name">{full_name}</div>
                <div class="sidebar-user-role">{role} Access</div>
            </div>
        </div>
        '''), unsafe_allow_html=True)

        st.markdown("<div style='font-size:0.75rem; font-weight:700; color:#94A3B8; text-transform:uppercase; letter-spacing:1px; margin: 12px 0 6px 4px;'>Navigation</div>", unsafe_allow_html=True)

        # Navigation Options
        nav_items = [
            ("Home", "staff_home", ":material/home:"),
            ("Customers", "customers", ":material/group:"),
            ("Trips", "trips", ":material/flight_takeoff:"),
            ("Documents", "documents", ":material/folder_open:"),
            ("Smart Intake", "smart_intake", ":material/person_add:"),
            ("Smart Upload", "smart_upload", ":material/upload_file:"),
            ("Document Review", "document_review", ":material/rate_review:"),
            ("Vault Search", "vault_search", ":material/search:"),
        ]

        for label, target_page, icon_name in nav_items:
            is_active = (current_page == target_page) or (
                target_page == "customers" and current_page == "customer_workspace"
            ) or (
                target_page == "trips" and current_page == "trip_workspace"
            )

            btn_type = "primary" if is_active else "secondary"
            if st.button(label, key=f"sb_nav_{target_page}", type=btn_type, icon=icon_name, use_container_width=True):
                # Clean query parameters when switching top-level navigation
                if target_page in ["staff_home", "customers", "trips", "documents", "smart_intake", "smart_upload", "vault_search"]:
                    st.query_params.clear()
                st.session_state['nav_page'] = target_page
                st.query_params.page = target_page
                st.rerun()

        st.markdown("<hr style='margin: 18px 0; border: none; border-top: 1px solid #E5EAF1;'>", unsafe_allow_html=True)

        if st.button("Logout", key="sb_logout_btn", icon=":material/logout:", use_container_width=True):
            import auth_services
            token = st.session_state.get('session_token')
            if token:
                auth_services.logout(token)
            st.session_state.clear()
            st.query_params.clear()
            st.rerun()


def render_top_nav():
    """
    Backwards compatibility: Replaces legacy truncated horizontal buttons
    with a clean, unobtrusive top identity strip.
    """
    # Simply ensure CSS is active; sidebar handles primary navigation.
    pass
