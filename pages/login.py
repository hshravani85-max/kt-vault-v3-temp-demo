import streamlit as st
import textwrap
import auth_services
import ui_helpers

# Self-healing resolution in case of long-running process module caching
if not hasattr(ui_helpers, 'render_logo_html'):
    import importlib
    try:
        importlib.reload(ui_helpers)
    except Exception:
        pass

render_logo_html = getattr(ui_helpers, 'render_logo_html', None)
inject_custom_css = getattr(ui_helpers, 'inject_custom_css', lambda: None)


def render_login():
    inject_custom_css()
    
    col1, col2, col3 = st.columns([1.1, 1.8, 1.1])
    with col2:
        logo_html = render_logo_html(max_width="320px") if render_logo_html else None
        if logo_html:
            st.markdown(textwrap.dedent(f"""
            <div style="background:#FFFFFF; border:1px solid #E5EAF1; border-radius:14px; padding:28px 32px 20px 32px; margin-top:30px; margin-bottom:16px; box-shadow:0 4px 12px rgba(11,35,72,0.06); text-align:center;">
                {logo_html}
                <h2 style="margin:12px 0 0 0; color:#0B2348; font-weight:800; font-size:1.45rem;">Document Vault</h2>
                <p style="margin:4px 0 0 0; color:#64748B; font-size:0.86rem;">Khanna Travels Secure Authentication</p>
            </div>
            """), unsafe_allow_html=True)
        else:
            st.markdown(textwrap.dedent("""
            <div style="background:#FFFFFF; border:1px solid #E5EAF1; border-radius:14px; padding:32px 32px 24px 32px; margin-top:35px; margin-bottom:16px; box-shadow:0 4px 12px rgba(11,35,72,0.06); text-align:center;">
                <div style="font-size:0.8rem; font-weight:700; letter-spacing:2px; color:#0875B8; text-transform:uppercase;">KHANNA TRAVELS</div>
                <h2 style="margin:4px 0 0 0; color:#0B2348; font-weight:800; font-size:1.55rem;">Document Vault</h2>
                <p style="margin:6px 0 0 0; color:#64748B; font-size:0.86rem;">Staff & Supervisor Portal Authentication</p>
            </div>
            """), unsafe_allow_html=True)

        mfa_stage = st.session_state.get('mfa_stage', 'login')

        # -------------------------------------------------------------
        # STAGE 1: Standard Username & Password Entry
        # -------------------------------------------------------------
        if mfa_stage == 'login':
            with st.container():
                st.markdown("<h4 style='color:#0B2348; margin-bottom:12px;'>Sign In</h4>", unsafe_allow_html=True)
                username = st.text_input("Username", key="login_username_input")
                password = st.text_input("Password", type="password", key="login_password_input")
                st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

                if st.button("Sign In to KT Vault", type="primary", use_container_width=True, key="login_submit_btn", icon=":material/login:"):
                    if not username or not password:
                        st.error("Please provide both username and password.")
                    else:
                        clean_username = username.strip()
                        try:
                            auth_res = auth_services.initiate_login(clean_username, password)
                            if not auth_res:
                                st.error("Invalid username or password.")
                            elif auth_res.get("status") == "MFA_REQUIRED":
                                st.session_state["pending_mfa"] = auth_res
                                st.session_state["mfa_stage"] = "verify"
                                st.rerun()
                            elif auth_res.get("status") == "MFA_ENROLLMENT_REQUIRED":
                                st.session_state["pending_mfa"] = auth_res
                                st.session_state["mfa_stage"] = "enroll"
                                st.rerun()
                            else:
                                st.error("Multi-Factor Authentication (MFA) challenge or setup is required before access can be granted.")
                        except PermissionError as pe:
                            st.error(str(pe))

        # -------------------------------------------------------------
        # STAGE 2A: TOTP One-Time Passcode Verification (Enrolled User)
        # -------------------------------------------------------------
        elif mfa_stage == 'verify':
            pending = st.session_state.get("pending_mfa", {})
            user_display = pending.get("username", "your account")

            st.markdown(f"""
            <div style="background:#F0FDF4; border:1px solid #BBF7D0; border-radius:10px; padding:16px; margin-bottom:16px;">
                <div style="font-weight:700; color:#166534; font-size:1.05rem;">🔐 Two-Factor Authentication</div>
                <div style="color:#15803D; font-size:0.88rem; margin-top:4px;">
                    Enter the 6-digit code from your authenticator app for <b>{user_display}</b>.
                </div>
            </div>
            """, unsafe_allow_html=True)

            totp_code = st.text_input("6-Digit Authenticator Code", max_chars=6, key="mfa_code_input", placeholder="000000")
            
            st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
            if st.button("Verify & Enter Vault", type="primary", use_container_width=True, key="mfa_verify_btn", icon=":material/verified_user:"):
                if not totp_code or len(totp_code.strip()) != 6:
                    st.error("Please enter a valid 6-digit verification code.")
                else:
                    try:
                        session = auth_services.complete_mfa_login(pending["temp_token"], totp_code.strip())
                        st.session_state['session_token'] = session['token']
                        st.session_state['user_full_name'] = session['full_name']
                        st.session_state['user_role'] = session['role']
                        st.session_state.pop("mfa_stage", None)
                        st.session_state.pop("pending_mfa", None)
                        st.success("MFA verified successfully. Redirecting...")
                        st.session_state["nav_page"] = "staff_home"
                        st.query_params.page = "staff_home"
                        st.rerun()
                    except PermissionError as pe:
                        st.error(str(pe))

            with st.expander("🔑 Emergency: Use Single-Use Recovery Code"):
                rec_code = st.text_input("Recovery Code", placeholder="KTV-XXXX-XXXX-XXXX", key="mfa_rec_code_input")
                if st.button("Authenticate with Recovery Code", key="mfa_rec_submit_btn"):
                    if not rec_code:
                        st.error("Please enter your recovery code.")
                    else:
                        try:
                            session = auth_services.complete_mfa_recovery_login(pending["temp_token"], rec_code.strip())
                            st.session_state['session_token'] = session['token']
                            st.session_state['user_full_name'] = session['full_name']
                            st.session_state['user_role'] = session['role']
                            st.session_state.pop("mfa_stage", None)
                            st.session_state.pop("pending_mfa", None)
                            st.success("Recovery code accepted. Redirecting...")
                            st.session_state["nav_page"] = "staff_home"
                            st.query_params.page = "staff_home"
                            st.rerun()
                        except PermissionError as pe:
                            st.error(str(pe))

            st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
            if st.button("← Back to Sign In", use_container_width=True, key="mfa_back_btn"):
                st.session_state["mfa_stage"] = "login"
                st.session_state.pop("pending_mfa", None)
                st.rerun()

        # -------------------------------------------------------------
        # STAGE 2B: MFA Enrollment & QR Code Setup (Unenrolled User)
        # -------------------------------------------------------------
        elif mfa_stage == 'enroll':
            pending = st.session_state.get("pending_mfa", {})
            user_display = pending.get("username", "your account")

            # Check if enrollment just completed and we are displaying recovery codes
            if st.session_state.get("mfa_enrollment_saved"):
                new_codes = st.session_state.get("new_recovery_codes", [])
                st.markdown("""
                <div style="background:#FFFBEB; border:1px solid #FCD34D; border-radius:10px; padding:18px; margin-bottom:18px;">
                    <div style="font-weight:700; color:#B45309; font-size:1.1rem;">⚠️ Emergency Recovery Codes</div>
                    <div style="color:#92400E; font-size:0.88rem; margin-top:6px; line-height:1.45;">
                        Save these <b>8 single-use recovery codes</b> in a secure password manager or safe place.
                        If you ever lose or replace your office phone, each recovery code can be used once to access KT Vault.
                    </div>
                </div>
                """, unsafe_allow_html=True)

                codes_text = "\n".join(new_codes)
                st.code(codes_text, language="text")

                if st.button("I Have Stored My Recovery Codes — Enter KT Vault", type="primary", use_container_width=True, key="mfa_enroll_done_btn", icon=":material/check_circle:"):
                    enrolled_session = st.session_state.get("enrolled_session", {})
                    st.session_state['session_token'] = enrolled_session.get('token')
                    st.session_state['user_full_name'] = enrolled_session.get('full_name')
                    st.session_state['user_role'] = enrolled_session.get('role')
                    st.session_state.pop("mfa_stage", None)
                    st.session_state.pop("pending_mfa", None)
                    st.session_state.pop("new_recovery_codes", None)
                    st.session_state.pop("mfa_enrollment_saved", None)
                    st.session_state.pop("enrolled_session", None)
                    st.session_state.pop("mfa_regen_banner", None)
                    st.session_state["nav_page"] = "staff_home"
                    st.query_params.page = "staff_home"
                    st.rerun()

            else:
                st.markdown(f"""
                <div style="background:#EFF6FF; border:1px solid #BFDBFE; border-radius:12px; padding:18px; margin-bottom:16px;">
                    <div style="font-weight:700; color:#1E40AF; font-size:1.1rem;">🛡️ Set Up Two-Factor Authentication (First-Time Setup)</div>
                    <div style="color:#1D4ED8; font-size:0.88rem; margin-top:6px; line-height:1.45;">
                        Protect your account (<b>{user_display}</b>) with an Authenticator app on your phone.
                        Follow the 4 simple steps below to complete setup.
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if st.session_state.get("mfa_regen_banner"):
                    st.warning(st.session_state["mfa_regen_banner"])

                # Step-by-step instructions
                st.markdown("""
                **Step 1: Open Authenticator App on Your Office Phone**
                * Open **Google Authenticator**, **Microsoft Authenticator**, or **1Password**.
                * Tap the **+** (Add Account) button.
                * In Microsoft Authenticator: Tap **+** &rarr; select **Other (Google, Facebook, etc.)** &rarr; **Scan QR code** *(for Google Authenticator or 1Password: tap **+** &rarr; **Scan a QR code**)*.
                """)

                st.markdown("**Step 2: Scan the QR Code Below**")
                qr_png = pending.get("qr_png")
                if qr_png:
                    st.image(qr_png, caption="Point your phone's camera at this QR code", width=220)

                with st.expander("Can't scan with camera? View manual secret key"):
                    st.caption("If your camera cannot scan the code, tap 'Enter a setup key' in your app and enter:")
                    st.code(pending.get("secret", ""), language="text")

                st.markdown("""
                **Step 3: Enter the 6-Digit Code from Your App**
                * Look at the 6-digit code displayed under **Khanna Travels Vault**.
                * ⏱️ *The code changes automatically approximately every **30 seconds**. Enter the code with a few seconds remaining before it refreshes.*
                """)

                # Visual 30-second cycle hint
                import time
                remaining_in_cycle = 30 - (int(time.time()) % 30)
                st.caption(f"ℹ️ Current 30-second code cycle: approximately **{remaining_in_cycle}s** remaining in this cycle.")

                enroll_code = st.text_input("6-Digit Verification Code", max_chars=6, key="mfa_enroll_input", placeholder="000000")

                st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
                if st.button("Verify & Complete Setup", type="primary", use_container_width=True, key="mfa_enroll_submit_btn", icon=":material/verified:"):
                    if not enroll_code or len(enroll_code.strip()) != 6:
                        st.error("Please enter the 6-digit code shown in your Authenticator app.")
                    else:
                        try:
                            session, rec_codes = auth_services.complete_mfa_enrollment(
                                pending["temp_token"], enroll_code.strip()
                            )
                            st.session_state["mfa_enrollment_saved"] = True
                            st.session_state["new_recovery_codes"] = rec_codes
                            st.session_state["enrolled_session"] = session
                            st.session_state.pop("mfa_regen_banner", None)
                            st.rerun()
                        except PermissionError as pe:
                            st.error(str(pe))

                st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

                # Reset / Regenerate option
                with st.container():
                    st.markdown("---")
                    st.markdown("<div style='font-weight:600; color:#475569; font-size:0.9rem;'>Need to Start Over?</div>", unsafe_allow_html=True)
                    st.caption("If your phone scanned an older QR code or if you are getting an error, click below to generate a fresh QR code.")

                    col_regen, col_cancel = st.columns([1, 1])
                    with col_regen:
                        if st.button("🔄 Start Fresh / Regenerate QR Code", use_container_width=True, key="mfa_regen_btn"):
                            try:
                                new_challenge = auth_services.regenerate_mfa_enrollment(pending["temp_token"])
                                st.session_state["pending_mfa"] = new_challenge
                                st.session_state["mfa_regen_banner"] = (
                                    "⚠️ New QR code generated. IMPORTANT: If you already have 'Khanna Travels Vault' "
                                    "in your authenticator app, please delete that old entry first, then scan this new QR code."
                                )
                                st.rerun()
                            except PermissionError as pe:
                                st.error(str(pe))

                    with col_cancel:
                        if st.button("← Cancel & Sign In Again", use_container_width=True, key="mfa_enroll_cancel_btn"):
                            st.session_state["mfa_stage"] = "login"
                            st.session_state.pop("pending_mfa", None)
                            st.session_state.pop("mfa_regen_banner", None)
                            st.rerun()

                with st.expander("🕒 Troubleshooting: Is your computer clock synchronized?"):
                    st.markdown("""
                    If valid codes continue to be rejected, your computer clock may have drifted from official time.
                    
                    **How to synchronize your device clock:**
                    - **Windows:** Right-click taskbar clock -> **Adjust date/time** -> enable **Set time automatically** -> **Sync now**.
                    - **macOS / Mobile:** Enable automatic network date & time (NTP) in **Date & Time** settings.
                    """)


render_login()
