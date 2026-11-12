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

# Refresh cached AZAPI adapter automatically if Streamlit Secrets changed AZAPI settings
try:
    import azapi_adapter as _az_mod
    if getattr(_az_mod, "_default_adapter", None) is not None:
        _cur_cfg = _az_mod._default_adapter.config
        _env_en = os.environ.get("AZAPI_ENABLED", "").lower().strip() in ("1", "true", "yes", "on")
        _env_key = (os.environ.get("AZAPI_API_KEY") or os.environ.get("AZAPI_AUTH_TOKEN") or "").strip()
        _env_base = (os.environ.get("AZAPI_BASE_URL") or _az_mod.DEFAULT_BASE_URL).strip().rstrip("/")
        if _cur_cfg.enabled != _env_en or _cur_cfg.api_key != _env_key or _cur_cfg.base_url != _env_base:
            _az_mod.reset_azapi_adapter()
except Exception:
    pass

import demo_bootstrap
demo_bootstrap.ensure_demo_vault()

runpy.run_path(os.path.join(APP_DIR, "app.py"), run_name="__main__")
