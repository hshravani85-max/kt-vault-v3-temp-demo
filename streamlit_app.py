"""
KT Vault V3 - Hosted Temporary Demo Entrypoint (streamlit_app.py)

Loads protected runtime configuration from Streamlit Secrets (or host env vars),
bootstraps the isolated synthetic demo vault if enabled, and runs app.py unchanged.
"""

import os
import runpy
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

# Populate os.environ from Streamlit Cloud / host secrets before any app imports
# Always refresh KT_* and AZAPI_* keys so in-place Streamlit Secrets updates take effect cleanly
try:
    import streamlit as st
    for _k, _v in st.secrets.items():
        if isinstance(_v, (str, int, float, bool)):
            _ks = str(_k)
            if _ks.startswith(("KT_", "AZAPI_")) or _ks not in os.environ:
                os.environ[_ks] = str(_v)
except Exception:
    pass

import demo_bootstrap
demo_bootstrap.ensure_demo_vault()

runpy.run_path(os.path.join(APP_DIR, "app.py"), run_name="__main__")
