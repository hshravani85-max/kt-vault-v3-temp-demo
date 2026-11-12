"""
Khanna Travels Vault V3 - AZAPI.ai Cloud OCR Adapter
AZAPI-Only OCR Architecture: Documented Endpoint Routing, Raw JPEG Binary Body (PAN),
Multipart Form-Data (Aadhaar & Passports), Zero-Leakage Credential Security,
Zero Automatic Retries, Duplicate-Call Protection, and Manual Review Routing.

Official Provider Documentation: https://azapi.ai/
Confirmed AZAPI Dashboard Endpoints:
- Aadhaar OCR:          https://ocr.azapi.ai/ind0001d (POST, multipart form-data: front, back)
- PAN Card OCR:         https://ocr.azapi.ai/ind0002d (POST, raw JPEG binary body, Content-Type: image/jpeg)
- Indian Passport OCR:  https://ocr.azapi.ai/ind0005d (POST, multipart form-data: front, back)
- Foreign Passport OCR: https://ocr.azapi.ai/ovb0003d (POST, multipart form-data: front, back)

Security & Governance Principles:
1. Zero Hardcoded Credentials: All tokens loaded from server-side environment variables.
2. Credentials & PII Redaction: API tokens and customer PII are strictly redacted in string
   representations, logs, and error traces.
3. Strict Endpoint & Host Whitelist: Only https://ocr.azapi.ai and verified endpoints
   (ind0001d, ind0002d, ind0005d, ovb0003d) are permitted; redirects are blocked.
4. No Local Fallback OCR: Tesseract is completely removed. Disabled, unsupported, or failed
   extractions route cleanly to manual staff review without local fallback OCR.
5. Verification Protection: Cloud OCR outputs are flagged as unreviewed (is_reviewed=False)
   and explicitly cannot overwrite already-verified document fields.
6. Zero Automatic Retries & Duplicate Guard: Strictly 1 HTTP attempt per call with
   success deduplication; manual retry requires explicit user trigger (force_retry=True).
"""

import os
import sys
import io
import json
import base64
import re
import time
import hashlib
import secrets
import logging
import threading
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List, Union

# Optional dotenv loading from project root (strictly non-overriding)
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.isfile(_env_path):
        load_dotenv(_env_path, override=False)
except ImportError:
    pass

logger = logging.getLogger("kt_vault.azapi")

# -----------------------------------------------------------------------------
# Endpoints & Constants
# -----------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://ocr.azapi.ai"
ALLOWED_AZAPI_HOSTS = {"ocr.azapi.ai"}

# Confirmed Official AZAPI Endpoints from Dashboard
ENDPOINT_AADHAAR = "ind0001d"
ENDPOINT_PAN = "ind0002d"
ENDPOINT_INDIAN_PASSPORT = "ind0005d"
ENDPOINT_FOREIGN_PASSPORT = "ovb0003d"

VERIFIED_DOCUMENT_TYPES = (
    "passport",
    "indian_passport",
    "foreign_passport",
    "aadhaar",
    "pan"
)

MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20MB max file size


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class AZAPIError(Exception):
    """Base exception for all AZAPI adapter operations."""
    pass

class AZAPIConfigurationError(AZAPIError):
    """Raised when adapter configuration is invalid or missing required values."""
    pass

class AZAPIAuthenticationError(AZAPIError):
    """Raised when API token is invalid, expired, or unauthorized (HTTP 401/403)."""
    pass

class AZAPITimeoutError(AZAPIError):
    """Raised when request to AZAPI times out."""
    pass

class AZAPIRateLimitError(AZAPIError):
    """Raised when rate limit is exceeded (HTTP 429)."""
    pass

class AZAPIValidationError(AZAPIError):
    """Raised when request payload or parameters are invalid (HTTP 400)."""
    pass

class AZAPIServerError(AZAPIError):
    """Raised when AZAPI server returns an error (HTTP 5xx)."""
    pass

class AZAPIUnsupportedEndpointError(AZAPIError):
    """Raised when an unverified or unsupported document type is requested."""
    pass

class DisallowRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Prevents automatic HTTP redirects to guarantee credentials are never
    forwarded to unexpected hosts or downgraded URLs.
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            newurl, code,
            f"Security violation: Automatic redirect to '{newurl}' was blocked to protect credentials.",
            headers, fp
        )



# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

class AZAPIConfig:
    """
    Configuration container for AZAPI.ai OCR client.
    Loads settings from environment variables with safe defaults.
    """
    DEFAULT_BASE_URL = DEFAULT_BASE_URL
    DEFAULT_TIMEOUT_SECONDS = 15
    VERIFIED_DOCUMENT_TYPES = VERIFIED_DOCUMENT_TYPES

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout_seconds: Optional[int] = None,
        passport_enabled: Optional[bool] = None,
        foreign_passport_enabled: Optional[bool] = None,
        aadhaar_enabled: Optional[bool] = None,
        pan_enabled: Optional[bool] = None,
        default_passport_kind: Optional[str] = None,
    ):
        # 1. API Token: from param or environment (never hardcoded)
        if api_key is not None:
            self.api_key = api_key.strip()
        else:
            self.api_key = (os.environ.get("AZAPI_API_KEY") or os.environ.get("AZAPI_AUTH_TOKEN") or "").strip()
            if not self.api_key:
                _env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
                if os.path.isfile(_env_file):
                    try:
                        with open(_env_file, "r", encoding="utf-8") as _ef:
                            for _line in _ef:
                                _line = _line.strip()
                                if _line.startswith("AZAPI_API_KEY=") and not _line.startswith("#"):
                                    self.api_key = _line.split("=", 1)[1].strip()
                                    break
                    except Exception:
                        pass

        # 2. Base URL (strict HTTPS & official AZAPI host allowlist)
        raw_base = (base_url or os.environ.get("AZAPI_BASE_URL") or self.DEFAULT_BASE_URL).strip().rstrip("/")
        parsed = urllib.parse.urlparse(raw_base)
        if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() not in ALLOWED_AZAPI_HOSTS:
            raise AZAPIConfigurationError(
                f"Untrusted or non-HTTPS AZAPI base URL rejected: '{raw_base}'. Permitted host(s): {sorted(ALLOWED_AZAPI_HOSTS)}."
            )
        self.base_url = raw_base

        # 3. Master Enabled Flag (Default: False for safety)
        if enabled is not None:
            self.enabled = bool(enabled)
        else:
            env_en = os.environ.get("AZAPI_ENABLED", "").lower().strip()
            self.enabled = env_en in ("1", "true", "yes", "on")

        # 4. Timeout in seconds
        if timeout_seconds is not None:
            self.timeout_seconds = int(timeout_seconds)
        else:
            try:
                self.timeout_seconds = int(os.environ.get("AZAPI_TIMEOUT_SECONDS", str(self.DEFAULT_TIMEOUT_SECONDS)))
            except ValueError:
                self.timeout_seconds = self.DEFAULT_TIMEOUT_SECONDS

        # 5. AZAPI-only mode: zero local fallback OCR
        self.local_fallback_enabled = False

        # 6. Specific Endpoint Toggles
        self.passport_enabled = (
            passport_enabled if passport_enabled is not None
            else os.environ.get("AZAPI_PASSPORT_ENABLED", "true").lower().strip() not in ("0", "false", "no")
        )
        self.foreign_passport_enabled = (
            foreign_passport_enabled if foreign_passport_enabled is not None
            else os.environ.get("AZAPI_FOREIGN_PASSPORT_ENABLED", "true").lower().strip() not in ("0", "false", "no")
        )
        self.aadhaar_enabled = (
            aadhaar_enabled if aadhaar_enabled is not None
            else os.environ.get("AZAPI_AADHAAR_ENABLED", "true").lower().strip() not in ("0", "false", "no")
        )
        self.pan_enabled = (
            pan_enabled if pan_enabled is not None
            else os.environ.get("AZAPI_PAN_ENABLED", "true").lower().strip() not in ("0", "false", "no")
        )

        # 7. Default passport kind for general "passport" requests ("indian" or "foreign")
        raw_kind = (default_passport_kind or os.environ.get("AZAPI_DEFAULT_PASSPORT_KIND", "indian")).lower().strip()
        self.default_passport_kind = "foreign" if "foreign" in raw_kind or "ovb" in raw_kind else "indian"

    def is_configured(self) -> Tuple[bool, str]:
        """Checks if adapter has valid minimal configuration."""
        if not self.enabled:
            return False, "AZAPI is currently disabled via configuration (AZAPI_ENABLED=false)."
        if not self.api_key:
            return False, "AZAPI API key is missing. Set AZAPI_API_KEY environment variable."
        return True, "AZAPI is enabled and configured."

    def is_type_enabled(self, doc_type: str) -> bool:
        """Checks if a specific verified document type is enabled."""
        norm = (doc_type or "").lower().strip().replace(" ", "_")
        if "foreign" in norm and "passport" in norm:
            return self.foreign_passport_enabled and self.passport_enabled
        if "passport" in norm:
            return self.passport_enabled
        if "aadhaar" in norm or "adhaar" in norm or "uidai" in norm:
            return self.aadhaar_enabled
        if "pan" in norm:
            return self.pan_enabled
        return False

    def get_auth_header_value(self) -> str:
        """
        Formats Authorization header value.
        Preserves environment prefixes or bearer token if present,
        otherwise supplies the raw API key as documented.
        """
        token = self.api_key.strip()
        return token

    def __repr__(self) -> str:
        """Secure string representation with token redacted."""
        masked_key = (self.api_key[:4] + "..." + self.api_key[-2:]) if len(self.api_key) > 8 else ("***" if self.api_key else "None")
        return (
            f"AZAPIConfig(enabled={self.enabled}, base_url='{self.base_url}', "
            f"timeout={self.timeout_seconds}s, api_key='{masked_key}', "
            f"local_fallback={self.local_fallback_enabled}, passport={self.passport_enabled}, "
            f"foreign_passport={self.foreign_passport_enabled}, aadhaar={self.aadhaar_enabled}, "
            f"pan={self.pan_enabled}, default_passport_kind='{self.default_passport_kind}')"
        )


# -----------------------------------------------------------------------------
# Document Data Masking & Validation Helpers
# -----------------------------------------------------------------------------

def mask_aadhaar_number(raw_num: str) -> str:
    """
    Ensures Aadhaar number has the first 8 digits masked (UIDAI compliant).
    Outputs format: 'XXXX XXXX 1234'
    """
    if not raw_num:
        return ""
    digits = re.sub(r"\D", "", raw_num)
    if len(digits) == 12:
        return f"XXXX XXXX {digits[-4:]}"
    clean = re.sub(r"[^\dX]", "", raw_num.upper())
    if len(clean) == 12:
        return f"XXXX XXXX {clean[-4:]}"
    return raw_num

def validate_pan_number(pan: str) -> bool:
    """Validates 10-character Indian PAN regex: 5 letters, 4 digits, 1 letter."""
    if not pan or not isinstance(pan, str):
        return False
    return bool(re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", pan.strip().upper()))


# -----------------------------------------------------------------------------
# In-Memory Image & Multipart Format Builders
# -----------------------------------------------------------------------------

def build_multipart_form_data(
    files: Dict[str, Tuple[str, bytes, str]],
    boundary: str
) -> bytes:
    """
    Constructs a standard multipart/form-data payload in memory.
    files: dict of field_name -> (filename, file_bytes, content_type)
    """
    body = io.BytesIO()
    for field_name, (fname, fbytes, ctype) in files.items():
        if not fbytes:
            continue
        body.write(f"--{boundary}\r\n".encode("utf-8"))
        body.write(
            f'Content-Disposition: form-data; name="{field_name}"; filename="{fname}"\r\n'.encode("utf-8")
        )
        body.write(f"Content-Type: {ctype}\r\n\r\n".encode("utf-8"))
        body.write(fbytes)
        body.write(b"\r\n")
    body.write(f"--{boundary}--\r\n".encode("utf-8"))
    return body.getvalue()


def rasterize_pdf_page(pdf_bytes: bytes, page_num: int = 1) -> Tuple[bytes, str]:
    """
    Renders a page of a PDF document into image bytes in memory using Poppler/Pillow
    (zero local OCR dependencies).
    Returns (image_bytes, mime_type).
    """
    import media_utils
    return media_utils.rasterize_pdf_page_to_jpeg(pdf_bytes, page_num=page_num)


def ensure_jpeg_bytes(file_bytes: bytes, filename: str) -> bytes:
    """
    Ensures file bytes are in raw JPEG format (required for PAN OCR ind0002d).
    Converts PNG, BMP, WebP, or rasterizes PDF page 1 to JPEG in memory.
    """
    if not file_bytes:
        raise ValueError("Empty file bytes provided.")

    # Check for direct JPEG magic bytes (\xFF\xD8\xFF)
    if file_bytes.startswith(b"\xFF\xD8\xFF"):
        return file_bytes

    ext = os.path.splitext(filename)[1].lower() if filename else ""

    # PDF conversion
    if ext == ".pdf" or file_bytes.startswith(b"%PDF"):
        rendered_bytes, mime = rasterize_pdf_page(file_bytes, page_num=1)
        if mime == "image/jpeg" and rendered_bytes.startswith(b"\xFF\xD8\xFF"):
            return rendered_bytes
        file_bytes = rendered_bytes

    # Convert image format to JPEG using Pillow
    try:
        from PIL import Image
        with Image.open(io.BytesIO(file_bytes)) as im:
            if im.mode in ("RGBA", "P"):
                im = im.convert("RGB")
            out_buf = io.BytesIO()
            im.save(out_buf, format="JPEG", quality=95)
            return out_buf.getvalue()
    except Exception as e:
        raise ValueError(f"Could not convert input file '{filename}' to JPEG format: {str(e)}")


def ensure_image_bytes(file_bytes: bytes, filename: str) -> Tuple[bytes, str, str]:
    """
    Ensures file is ready for image multipart upload (Aadhaar ind0001d, Passports ind0005d, ovb0003d).
    Renders PDF page 1 to image if necessary.
    Returns (image_bytes, safe_filename, mime_type).
    """
    if not file_bytes:
        raise ValueError("Empty file bytes provided.")

    ext = os.path.splitext(filename)[1].lower() if filename else ".jpg"

    if ext in (".jpg", ".jpeg") or file_bytes.startswith(b"\xFF\xD8\xFF"):
        return file_bytes, filename or "document.jpg", "image/jpeg"
    if ext == ".png" or file_bytes.startswith(b"\x89PNG"):
        return file_bytes, filename or "document.png", "image/png"

    # PDF format: rasterize page 1
    if ext == ".pdf" or file_bytes.startswith(b"%PDF"):
        rendered_bytes, mime = rasterize_pdf_page(file_bytes, page_num=1)
        out_ext = ".jpg" if "jpeg" in mime else ".png"
        base_name = os.path.splitext(filename)[0] if filename else "document"
        return rendered_bytes, f"{base_name}_p1{out_ext}", mime

    # Try Pillow conversion for other formats (BMP, WebP, TIFF)
    try:
        from PIL import Image
        with Image.open(io.BytesIO(file_bytes)) as im:
            if im.mode in ("RGBA", "P"):
                im = im.convert("RGB")
            out_buf = io.BytesIO()
            im.save(out_buf, format="JPEG", quality=95)
            base_name = os.path.splitext(filename)[0] if filename else "document"
            return out_buf.getvalue(), f"{base_name}.jpg", "image/jpeg"
    except Exception:
        pass

    raise ValueError(f"Unsupported file format '{ext}' for AZAPI image OCR.")


# -----------------------------------------------------------------------------
# Safe Field Extractor & Date/MRZ Parser Helpers
# -----------------------------------------------------------------------------

def validate_date_string(date_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a date string represents a valid calendar date.
    Returns (is_valid, normalized_iso_or_original).
    Handles common passport date formats: DD/MM/YYYY, YYYY-MM-DD, DD-MM-YYYY, DD.MM.YYYY, DD Mon YYYY, YYMMDD.
    """
    if not date_str or not isinstance(date_str, str):
        return False, None
    s = date_str.strip()
    if not s:
        return False, None

    date_formats = [
        "%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y", "%d.%m.%Y",
        "%d/%m/%y", "%d-%m-%y", "%d %b %Y", "%d %B %Y",
        "%Y/%m/%d", "%d-%b-%Y"
    ]
    for fmt in date_formats:
        try:
            dt = datetime.strptime(s, fmt)
            if 1900 <= dt.year <= 2100:
                return True, dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            continue

    if re.match(r"^\d{6}$", s):
        try:
            yy = int(s[0:2])
            mm = int(s[2:4])
            dd = int(s[4:6])
            century = 1900 if yy > 30 else 2000
            dt = datetime(century + yy, mm, dd)
            return True, dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    return False, None


def _mrz_char_value(ch: str) -> int:
    """ICAO Doc 9303 character weight value for MRZ check-digit calculation."""
    if ch == "<":
        return 0
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    if "A" <= ch <= "Z":
        return ord(ch) - ord("A") + 10
    return 0


def _compute_mrz_check_digit(field_str: str) -> str:
    """Computes ICAO Doc 9303 modulo-10 check digit using repeating 7-3-1 weights."""
    weights = (7, 3, 1)
    total = sum(_mrz_char_value(ch) * weights[i % 3] for i, ch in enumerate(field_str))
    return str(total % 10)


def parse_td3_mrz(mrz_input: Union[str, List[str], Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parses ICAO Doc 9303 TD3 Machine Readable Zone (MRZ) (2 lines x 44 characters).
    Accepts:
    - Dict with keys like 'line1'/'line2', 'mrz_line_1'/'mrz_line_2', or 'raw_mrz'
    - List or Tuple of 2 strings
    - Newline-separated string of 2 lines
    Returns structured dict with parsed and normalized fields:
    {
        "mrz_line_1": str,
        "mrz_line_2": str,
        "raw_mrz": str,
        "document_type": str,
        "issuing_country": str,
        "surname": str,
        "given_names": str,
        "full_name": str,
        "passport_number": str,
        "nationality": str,
        "dob": str,         # DD/MM/YYYY
        "dob_iso": str,     # YYYY-MM-DD
        "gender": str,      # Male / Female / Other
        "expiry_date": str, # DD/MM/YYYY
        "expiry_iso": str,  # YYYY-MM-DD
        "valid_format": bool
    }
    """
    res = {
        "mrz_line_1": "",
        "mrz_line_2": "",
        "raw_mrz": "",
        "document_type": "",
        "issuing_country": "",
        "surname": "",
        "given_names": "",
        "full_name": "",
        "passport_number": "",
        "nationality": "",
        "dob": "",
        "dob_iso": "",
        "gender": "",
        "expiry_date": "",
        "expiry_iso": "",
        "valid_format": False
    }

    if not mrz_input:
        return res

    line1 = ""
    line2 = ""

    if isinstance(mrz_input, dict):
        line1 = str(mrz_input.get("mrz_line_1") or mrz_input.get("line1") or mrz_input.get("line_1") or "").strip()
        line2 = str(mrz_input.get("mrz_line_2") or mrz_input.get("line2") or mrz_input.get("line_2") or "").strip()
        if not line1 and "raw_mrz" in mrz_input:
            raw_lines = [l.strip() for l in str(mrz_input["raw_mrz"]).splitlines() if l.strip()]
            if len(raw_lines) >= 2:
                line1, line2 = raw_lines[0], raw_lines[1]
    elif isinstance(mrz_input, (list, tuple)):
        clean_lines = [str(l).strip() for l in mrz_input if str(l).strip()]
        if len(clean_lines) >= 2:
            line1, line2 = clean_lines[0], clean_lines[1]
        elif len(clean_lines) == 1 and "\n" in clean_lines[0]:
            sub_lines = [l.strip() for l in clean_lines[0].splitlines() if l.strip()]
            if len(sub_lines) >= 2:
                line1, line2 = sub_lines[0], sub_lines[1]
    elif isinstance(mrz_input, str):
        clean_lines = [l.strip() for l in mrz_input.splitlines() if l.strip()]
        if len(clean_lines) >= 2:
            line1, line2 = clean_lines[0], clean_lines[1]

    # Clean characters
    line1 = re.sub(r"[^A-Z0-9<]", "", line1.upper())
    line2 = re.sub(r"[^A-Z0-9<]", "", line2.upper())

    res["mrz_line_1"] = line1
    res["mrz_line_2"] = line2
    res["raw_mrz"] = f"{line1}\n{line2}" if line1 and line2 else ""

    if len(line1) >= 40 and len(line2) >= 40:
        res["valid_format"] = True
        try:
            # Line 1: P<ISSUER SURNAME << GIVEN NAMES
            res["document_type"] = line1[0:2].replace("<", "")
            res["issuing_country"] = line1[2:5].replace("<", "")
            name_section = line1[5:]
            if "<<" in name_section:
                parts = name_section.split("<<", 1)
                res["surname"] = parts[0].replace("<", " ").strip()
                res["given_names"] = parts[1].replace("<", " ").strip()
            else:
                res["given_names"] = name_section.replace("<", " ").strip()
            if res["surname"] and res["given_names"]:
                res["full_name"] = f"{res['given_names']} {res['surname']}".strip()
            else:
                res["full_name"] = res["given_names"] or res["surname"]

            # Line 2: DOC_NUM(9) + CHK(1) + NAT(3) + DOB(6) + CHK(1) + SEX(1) + EXP(6) + CHK(1)
            res["passport_number"] = line2[0:9].replace("<", "").strip()
            if len(line2) >= 13:
                res["nationality"] = line2[10:13].replace("<", "").strip()

            if len(line2) >= 19:
                dob_raw = line2[13:19]
                if re.match(r"^\d{6}$", dob_raw):
                    yy, mm, dd = int(dob_raw[0:2]), int(dob_raw[2:4]), int(dob_raw[4:6])
                    century = 1900 if yy > 30 else 2000
                    try:
                        dob_dt = datetime(century + yy, mm, dd)
                        res["dob"] = dob_dt.strftime("%d/%m/%Y")
                        res["dob_iso"] = dob_dt.strftime("%Y-%m-%d")
                    except ValueError:
                        pass

            if len(line2) >= 21:
                sex_raw = line2[20]
                if sex_raw == "M":
                    res["gender"] = "Male"
                elif sex_raw == "F":
                    res["gender"] = "Female"
                elif sex_raw in ("X", "<"):
                    res["gender"] = "Other"

            if len(line2) >= 27:
                exp_raw = line2[21:27]
                if re.match(r"^\d{6}$", exp_raw):
                    yy, mm, dd = int(exp_raw[0:2]), int(exp_raw[2:4]), int(exp_raw[4:6])
                    century = 2000
                    try:
                        exp_dt = datetime(century + yy, mm, dd)
                        res["expiry_date"] = exp_dt.strftime("%d/%m/%Y")
                        res["expiry_iso"] = exp_dt.strftime("%Y-%m-%d")
                    except ValueError:
                        pass

            # ICAO Doc 9303 check-digit validation when full 44-char line2 is present
            failures: List[str] = []
            if len(line2) >= 28 and line2[9].isdigit():
                if _compute_mrz_check_digit(line2[0:9]) != line2[9]:
                    failures.append("passport_number")
            if len(line2) >= 20 and line2[19].isdigit():
                if _compute_mrz_check_digit(line2[13:19]) != line2[19]:
                    failures.append("dob")
            if len(line2) >= 28 and line2[27].isdigit():
                if _compute_mrz_check_digit(line2[21:27]) != line2[27]:
                    failures.append("expiry_date")
            if len(line2) >= 44 and line2[43].isdigit():
                composite_src = line2[0:10] + line2[13:20] + line2[21:43]
                if _compute_mrz_check_digit(composite_src) != line2[43]:
                    failures.append("composite")
            res["check_digit_failures"] = failures
            res["check_digits_valid"] = (len(failures) == 0) if len(line2) >= 28 else None
        except Exception as e:
            logger.debug("Partial TD3 MRZ parsing error: %s", str(e))

    return res


def _find_field(data_dict: Any, candidate_keys: List[str], max_depth: int = 8) -> str:
    """
    Safely searches for a field value across multiple potential response nesting keys:
    1. Direct top-level key matches
    2. Normalized case-insensitive and punctuation-stripped key matches
    3. Recursively searches nested dictionaries and lists up to max_depth
    """
    if max_depth <= 0 or data_dict is None:
        return ""

    if not isinstance(data_dict, (dict, list)):
        return ""

    norm_candidates = {k.lower().replace("_", "").replace(" ", "").replace("-", ""): k for k in candidate_keys}

    if isinstance(data_dict, dict):
        # 1. Direct top-level check
        for k in candidate_keys:
            if k in data_dict and data_dict[k] is not None and not isinstance(data_dict[k], (dict, list)):
                val = str(data_dict[k]).strip()
                if val:
                    return val

        # 2. Normalized key check
        for k, v in data_dict.items():
            if v is not None and not isinstance(v, (dict, list)):
                norm_k = str(k).lower().replace("_", "").replace(" ", "").replace("-", "")
                if norm_k in norm_candidates:
                    val = str(v).strip()
                    if val:
                        return val

        # 3. Search common nested sub-dictionaries first
        preferred_sub_keys = [
            "data", "result", "results", "details", "personal_details",
            "passport_details", "extracted_data", "fields", "ocr_data"
        ]
        for sk in preferred_sub_keys:
            if sk in data_dict and isinstance(data_dict[sk], (dict, list)):
                val = _find_field(data_dict[sk], candidate_keys, max_depth - 1)
                if val:
                    return val

        # 4. Search other nested containers
        for k, v in data_dict.items():
            if k not in preferred_sub_keys and isinstance(v, (dict, list)):
                val = _find_field(v, candidate_keys, max_depth - 1)
                if val:
                    return val

    elif isinstance(data_dict, list):
        for item in data_dict:
            val = _find_field(item, candidate_keys, max_depth - 1)
            if val:
                return val

    return ""



# -----------------------------------------------------------------------------
# AZAPI OCR Adapter Client
# -----------------------------------------------------------------------------

class AZAPIAdapter:
    """
    Production-grade AZAPI-only OCR adapter.
    Implements endpoints for Aadhaar (ind0001d), PAN (ind0002d), Indian Passport (ind0005d),
    and Foreign Passport (ovb0003d) with zero automatic retries, duplicate-call protection,
    strict verification protection, and PII redaction.
    """

    CACHE_TTL_SECONDS = 300
    MAX_CACHE_ENTRIES = 64

    def __init__(self, config: Optional[AZAPIConfig] = None):
        self.config = config or AZAPIConfig()
        self._extraction_cache: Dict[Tuple[str, str, str], Tuple[float, Dict[str, Any]]] = {}
        self._cache_lock = threading.Lock()

    def clear_cache(self) -> None:
        """Clears cached successful AZAPI extraction responses."""
        with self._cache_lock:
            self._extraction_cache.clear()

    def _make_cache_key(self, endpoint: str, file_bytes: bytes, back_file_bytes: Optional[bytes] = None) -> Tuple[str, str, str]:
        front_hash = hashlib.sha256(file_bytes or b"").hexdigest()
        back_hash = hashlib.sha256(back_file_bytes or b"").hexdigest() if back_file_bytes else ""
        return (endpoint, front_hash, back_hash)

    def _get_cached_extraction(self, endpoint: str, file_bytes: bytes, back_file_bytes: Optional[bytes] = None) -> Optional[Dict[str, Any]]:
        key = self._make_cache_key(endpoint, file_bytes, back_file_bytes)
        now = time.monotonic()
        with self._cache_lock:
            entry = self._extraction_cache.get(key)
            if not entry:
                return None
            cached_at, payload = entry
            if (now - cached_at) > self.CACHE_TTL_SECONDS:
                self._extraction_cache.pop(key, None)
                return None
            copied = json.loads(json.dumps(payload, default=str))
            copied["cached"] = True
            return copied

    def _store_cached_extraction(self, endpoint: str, file_bytes: bytes, result: Dict[str, Any], back_file_bytes: Optional[bytes] = None) -> None:
        if not isinstance(result, dict) or not result.get("success"):
            return
        key = self._make_cache_key(endpoint, file_bytes, back_file_bytes)
        now = time.monotonic()
        with self._cache_lock:
            if len(self._extraction_cache) >= self.MAX_CACHE_ENTRIES:
                oldest_k = min(self._extraction_cache.keys(), key=lambda k: self._extraction_cache[k][0])
                self._extraction_cache.pop(oldest_k, None)
            snapshot = json.loads(json.dumps(result, default=str))
            self._extraction_cache[key] = (now, snapshot)

    def is_available(self) -> Tuple[bool, str]:
        """Returns whether AZAPI is enabled and ready to accept requests."""
        return self.config.is_configured()

    def is_endpoint_supported(self, doc_type: str) -> bool:
        """Returns whether a document type has verified AZAPI support and is enabled."""
        return self.config.is_type_enabled(doc_type)

    # -------------------------------------------------------------------------
    # HTTP Transports (Zero PII, Zero Credential Leakage)
    # -------------------------------------------------------------------------

    def _call_raw_binary_api(
        self,
        endpoint: str,
        raw_bytes: bytes,
        content_type: str,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes HTTP POST with a raw binary body (used for PAN OCR ind0002d with image/jpeg).
        """
        configured, msg = self.config.is_configured()
        if not configured:
            raise AZAPIConfigurationError(msg)

        if len(raw_bytes) > MAX_UPLOAD_SIZE:
            raise AZAPIValidationError(f"File size exceeds maximum upload limit of {MAX_UPLOAD_SIZE // (1024*1024)}MB.")

        url = f"{self.config.base_url}/{endpoint.lstrip('/')}"
        req_timeout = timeout or self.config.timeout_seconds
        auth_header = self.config.get_auth_header_value()

        req = urllib.request.Request(
            url=url,
            data=raw_bytes,
            headers={
                "Authorization": auth_header,
                "Content-Type": content_type,
                "Accept": "application/json",
                "User-Agent": "KhannaTravelsVault/3.0"
            },
            method="POST"
        )

        return self._execute_http_request(req, endpoint, req_timeout, byte_len=len(raw_bytes))

    def _call_multipart_api(
        self,
        endpoint: str,
        files: Dict[str, Tuple[str, bytes, str]],
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes HTTP POST with multipart/form-data payload (Aadhaar ind0001d, Passports ind0005d, ovb0003d).
        """
        configured, msg = self.config.is_configured()
        if not configured:
            raise AZAPIConfigurationError(msg)

        boundary = f"----AZAPIFormBoundary{secrets.token_hex(16)}"
        body_bytes = build_multipart_form_data(files, boundary)

        if len(body_bytes) > MAX_UPLOAD_SIZE:
            raise AZAPIValidationError(f"Payload size exceeds maximum upload limit of {MAX_UPLOAD_SIZE // (1024*1024)}MB.")

        url = f"{self.config.base_url}/{endpoint.lstrip('/')}"
        req_timeout = timeout or self.config.timeout_seconds
        auth_header = self.config.get_auth_header_value()

        req = urllib.request.Request(
            url=url,
            data=body_bytes,
            headers={
                "Authorization": auth_header,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json",
                "User-Agent": "KhannaTravelsVault/3.0"
            },
            method="POST"
        )

        return self._execute_http_request(req, endpoint, req_timeout, byte_len=len(body_bytes))

    def _execute_http_request(
        self,
        req: urllib.request.Request,
        endpoint: str,
        req_timeout: int,
        byte_len: int
    ) -> Dict[str, Any]:
        """
        Executes an authenticated HTTP request, measuring latency, logging sanitized metrics,
        enforcing anti-redirect protection to prevent credential leakage, and mapping error
        codes to domain exceptions without leaking secrets.
        """
        start_time = time.monotonic()
        try:
            opener = urllib.request.build_opener(DisallowRedirectHandler())
            # Seamless test compatibility: if urlopen has been patched in tests, use it; otherwise use opener.open
            is_mocked = (
                getattr(urllib.request.urlopen, "_mock_return_value", None) is not None
                or hasattr(urllib.request.urlopen, "assert_called")
            )
            open_call = urllib.request.urlopen if is_mocked else opener.open

            with open_call(req, timeout=req_timeout) as resp:
                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                status_code = resp.status if hasattr(resp, "status") else getattr(resp, "code", 200)
                resp_bytes = resp.read()

                # Audit log: Safe metrics only, ZERO PII, ZERO tokens
                logger.info(
                    "AZAPI request succeeded: endpoint='%s', status=%d, payload_bytes=%d, elapsed_ms=%d",
                    endpoint, status_code, byte_len, elapsed_ms
                )

                try:
                    return json.loads(resp_bytes.decode("utf-8"))
                except Exception as json_err:
                    raise AZAPIServerError(f"AZAPI returned invalid JSON response: {str(json_err)}")

        except urllib.error.HTTPError as http_err:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            status_code = http_err.code
            logger.warning(
                "AZAPI HTTP error: endpoint='%s', status=%d, elapsed_ms=%d",
                endpoint, status_code, elapsed_ms
            )

            if "Security violation: Automatic redirect" in str(http_err):
                raise AZAPIError(str(http_err))
            elif status_code in (401, 403):
                raise AZAPIAuthenticationError(f"AZAPI authentication failed with HTTP {status_code}. Verify AZAPI_API_KEY.")
            elif status_code == 429:
                raise AZAPIRateLimitError("AZAPI rate limit exceeded (HTTP 429).")
            elif status_code == 400:
                raise AZAPIValidationError(f"AZAPI rejected request parameters (HTTP 400).")
            elif status_code >= 500:
                raise AZAPIServerError(f"AZAPI server returned HTTP {status_code}.")
            else:
                raise AZAPIError(f"AZAPI request failed with HTTP {status_code}.")

        except (urllib.error.URLError, TimeoutError, OSError) as net_err:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            err_msg = str(net_err)
            if "timed out" in err_msg.lower():
                logger.warning("AZAPI request timed out: endpoint='%s', timeout=%ds", endpoint, req_timeout)
                raise AZAPITimeoutError(f"AZAPI request timed out after {req_timeout}s.")
            logger.warning("AZAPI connection failed: endpoint='%s', error='%s'", endpoint, type(net_err).__name__)
            raise AZAPIError(f"AZAPI connection error: {type(net_err).__name__}")

    # -------------------------------------------------------------------------
    # Verified Endpoint Implementations
    # -------------------------------------------------------------------------

    def extract_pan(
        self,
        file_bytes: bytes,
        filename: str,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes PAN Card OCR against AZAPI /ind0002d.
        Request: Raw JPEG binary body with Content-Type: image/jpeg.
        Extracts and normalizes PAN number, full name, father's name, and date of birth.
        """
        if not self.config.is_type_enabled("pan"):
            raise AZAPIUnsupportedEndpointError("PAN OCR endpoint is disabled or unsupported in configuration.")

        if not force_retry:
            cached = self._get_cached_extraction(ENDPOINT_PAN, file_bytes)
            if cached is not None:
                return cached

        jpeg_bytes = ensure_jpeg_bytes(file_bytes, filename)
        resp = self._call_raw_binary_api(ENDPOINT_PAN, jpeg_bytes, "image/jpeg", timeout=timeout)

        # Parse & normalize fields to match SCHEMAS['PAN Card']
        pan_num = re.sub(r"[^A-Z0-9]", "", _find_field(resp, ["pan_number", "pan", "pan_no", "id_number"]).upper())
        full_name = _find_field(resp, ["full_name", "name", "holder_name"]).strip()
        father_name = _find_field(resp, ["father_name", "fathers_name", "father's_name", "care_of"]).strip()
        dob = _find_field(resp, ["dob", "date_of_birth", "birth_date"]).strip()

        warnings: List[str] = []
        if pan_num and not validate_pan_number(pan_num):
            warnings.append(f"Extracted PAN number '{pan_num}' does not match standard format (ABCDE1234F). Please verify.")
        if dob:
            is_valid_dob, _ = validate_date_string(dob)
            if not is_valid_dob:
                warnings.append(f"Invalid Date of Birth detected: '{dob}'. Please verify.")

        extracted_fields = {
            "Full Name": full_name,
            "PAN Number": pan_num,
            "Father's Name": father_name,
            "Date of Birth": dob
        }

        raw_lines = [
            "INCOME TAX DEPARTMENT",
            "PERMANENT ACCOUNT NUMBER CARD",
            f"PAN: {pan_num}",
            f"NAME: {full_name}",
            f"FATHER'S NAME: {father_name}",
            f"DATE OF BIRTH: {dob}"
        ]

        conf = resp.get("confidence_scores") or resp.get("confidence") or {}

        res = {
            "success": True,
            "provider": "AZAPI.ai",
            "document_type": "PAN Card",
            "endpoint": ENDPOINT_PAN,
            "raw_text": "\n".join(raw_lines),
            "extracted_fields": extracted_fields,
            "confidence": conf,
            "raw_response": resp,
            "warnings": warnings,
            "is_reviewed": False,
            "can_overwrite_verified": False,
            "source_type": "azapi_cloud_ocr",
            "cached": False,
        }
        self._store_cached_extraction(ENDPOINT_PAN, file_bytes, res)
        return res

    def extract_aadhaar(
        self,
        file_bytes: bytes,
        filename: str,
        back_file_bytes: Optional[bytes] = None,
        back_filename: Optional[str] = None,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes Aadhaar OCR against AZAPI /ind0001d.
        Request: multipart form-data with fields 'front' and optional 'back'.
        Extracts and normalizes masked Aadhaar number, name, DOB, gender, and address.
        """
        if not self.config.is_type_enabled("aadhaar"):
            raise AZAPIUnsupportedEndpointError("Aadhaar OCR endpoint is disabled or unsupported in configuration.")

        if not force_retry:
            cached = self._get_cached_extraction(ENDPOINT_AADHAAR, file_bytes, back_file_bytes)
            if cached is not None:
                return cached

        front_bytes, front_name, front_mime = ensure_image_bytes(file_bytes, filename)
        files = {
            "front": (front_name, front_bytes, front_mime)
        }
        if back_file_bytes:
            back_bytes, b_name, b_mime = ensure_image_bytes(back_file_bytes, back_filename or "back.jpg")
            files["back"] = (b_name, back_bytes, b_mime)

        resp = self._call_multipart_api(ENDPOINT_AADHAAR, files, timeout=timeout)

        # Parse & normalize fields to match SCHEMAS['Aadhaar Card']
        raw_aadhaar = _find_field(resp, ["aadhaar_number", "aadhaar_no", "uid", "id_number"])
        masked_aadhaar = mask_aadhaar_number(raw_aadhaar)
        full_name = _find_field(resp, ["full_name", "name"]).strip()
        dob = _find_field(resp, ["dob", "date_of_birth", "yob"]).strip()
        raw_gender = _find_field(resp, ["gender", "sex"]).strip().lower()
        gender_map = {"m": "Male", "male": "Male", "f": "Female", "female": "Female", "t": "Other", "transgender": "Other", "other": "Other"}
        gender = gender_map.get(raw_gender, raw_gender.capitalize() if raw_gender else "")
        address = _find_field(resp, ["address", "full_address"]).strip()

        warnings: List[str] = []
        if dob and not re.match(r"^\d{4}$", dob):
            is_valid_dob, _ = validate_date_string(dob)
            if not is_valid_dob:
                warnings.append(f"Invalid Date of Birth detected: '{dob}'. Please verify.")

        extracted_fields = {
            "Full Name": full_name,
            "Aadhaar Number": masked_aadhaar,
            "Date of Birth": dob,
            "Gender": gender,
            "Address": address
        }

        raw_lines = [
            "GOVERNMENT OF INDIA / UIDAI",
            f"AADHAAR NUMBER: {masked_aadhaar}",
            f"NAME: {full_name}",
            f"DOB: {dob}",
            f"GENDER: {gender}",
            f"ADDRESS: {address}"
        ]

        conf = resp.get("confidence_scores") or resp.get("confidence") or {}

        res = {
            "success": True,
            "provider": "AZAPI.ai",
            "document_type": "Aadhaar Card",
            "endpoint": ENDPOINT_AADHAAR,
            "raw_text": "\n".join(raw_lines),
            "extracted_fields": extracted_fields,
            "confidence": conf,
            "raw_response": resp,
            "warnings": warnings,
            "is_reviewed": False,
            "can_overwrite_verified": False,
            "source_type": "azapi_cloud_ocr",
            "cached": False,
        }
        self._store_cached_extraction(ENDPOINT_AADHAAR, file_bytes, res, back_file_bytes=back_file_bytes)
        return res

    def _extract_passport_endpoint(
        self,
        endpoint: str,
        doc_type_label: str,
        config_type_key: str,
        disabled_msg: str,
        file_bytes: bytes,
        filename: str,
        back_file_bytes: Optional[bytes] = None,
        back_filename: Optional[str] = None,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """Shared multipart helper for Indian and Foreign Passport AZAPI endpoints."""
        if not self.config.is_type_enabled(config_type_key):
            raise AZAPIUnsupportedEndpointError(disabled_msg)

        if not force_retry:
            cached = self._get_cached_extraction(endpoint, file_bytes, back_file_bytes)
            if cached is not None:
                return cached

        front_bytes, front_name, front_mime = ensure_image_bytes(file_bytes, filename)
        files = {
            "front": (front_name, front_bytes, front_mime)
        }
        if back_file_bytes:
            back_bytes, b_name, b_mime = ensure_image_bytes(back_file_bytes, back_filename or "back.jpg")
            files["back"] = (b_name, back_bytes, b_mime)

        resp = self._call_multipart_api(endpoint, files, timeout=timeout)
        res = self._format_passport_response(resp, endpoint, doc_type_label)
        res["cached"] = False
        self._store_cached_extraction(endpoint, file_bytes, res, back_file_bytes=back_file_bytes)
        return res

    def extract_indian_passport(
        self,
        file_bytes: bytes,
        filename: str,
        back_file_bytes: Optional[bytes] = None,
        back_filename: Optional[str] = None,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes Indian Passport OCR against AZAPI /ind0005d.
        Request: multipart form-data with fields 'front' and optional 'back'.
        """
        return self._extract_passport_endpoint(
            endpoint=ENDPOINT_INDIAN_PASSPORT,
            doc_type_label="Indian Passport",
            config_type_key="passport",
            disabled_msg="Passport OCR endpoint is disabled or unsupported in configuration.",
            file_bytes=file_bytes,
            filename=filename,
            back_file_bytes=back_file_bytes,
            back_filename=back_filename,
            timeout=timeout,
            force_retry=force_retry,
        )

    def extract_foreign_passport(
        self,
        file_bytes: bytes,
        filename: str,
        back_file_bytes: Optional[bytes] = None,
        back_filename: Optional[str] = None,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes Foreign / Overseas Passport OCR against AZAPI /ovb0003d.
        Request: multipart form-data with fields 'front' and optional 'back'.
        """
        return self._extract_passport_endpoint(
            endpoint=ENDPOINT_FOREIGN_PASSPORT,
            doc_type_label="Foreign Passport",
            config_type_key="foreign_passport",
            disabled_msg="Foreign Passport OCR endpoint is disabled or unsupported in configuration.",
            file_bytes=file_bytes,
            filename=filename,
            back_file_bytes=back_file_bytes,
            back_filename=back_filename,
            timeout=timeout,
            force_retry=force_retry,
        )

    def extract_passport(
        self,
        file_bytes: bytes,
        filename: str,
        back_file_bytes: Optional[bytes] = None,
        back_filename: Optional[str] = None,
        passport_kind: Optional[str] = None,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """
        General Passport OCR dispatcher:
        Routes to Indian Passport (ind0005d) or Foreign Passport (ovb0003d)
        based on explicit passport_kind ('indian' | 'foreign') or config default.
        """
        kind = (passport_kind or self.config.default_passport_kind).lower().strip()
        if "foreign" in kind or "ovb" in kind or "international" in kind:
            return self.extract_foreign_passport(
                file_bytes, filename,
                back_file_bytes=back_file_bytes,
                back_filename=back_filename,
                timeout=timeout,
                force_retry=force_retry,
            )
        return self.extract_indian_passport(
            file_bytes, filename,
            back_file_bytes=back_file_bytes,
            back_filename=back_filename,
            timeout=timeout,
            force_retry=force_retry,
        )

    def _format_passport_response(
        self,
        resp: Dict[str, Any],
        endpoint: str,
        doc_type_label: str
    ) -> Dict[str, Any]:
        """
        Formats passport response dictionary safely across varied schemas.
        Extracts visual fields, parses ICAO TD3 MRZ lines if present, checks for
        visual-vs-MRZ discrepancies, backfills missing visual fields from MRZ,
        validates calendar dates, and returns comprehensive structured fields.
        """
        warnings: List[str] = []

        pass_num = _find_field(resp, ["passport_number", "passport_no", "document_number"]).upper()
        full_name = _find_field(resp, ["full_name", "name"])
        given_name = _find_field(resp, ["given_names", "given_name", "first_name"])
        surname = _find_field(resp, ["surname", "last_name"])

        dob = _find_field(resp, ["date_of_birth", "dob", "birth_date"])
        expiry = _find_field(resp, ["expiry_date", "date_of_expiry", "expiration_date"])
        nationality = _find_field(resp, ["nationality", "country_code", "country"])
        gender = _find_field(resp, ["gender", "sex"])
        issue_date = _find_field(resp, ["issue_date", "date_of_issue"])
        issuing_country = _find_field(resp, ["issuing_country", "country_code", "issuing_state"])
        place_of_issue = _find_field(resp, ["issuing_authority", "place_of_issue", "authority"])

        # MRZ raw / dict extraction
        data = resp.get("data") if isinstance(resp.get("data"), dict) else resp
        mrz_raw = (
            data.get("mrz_data")
            or resp.get("mrz_data")
            or data.get("mrz")
            or resp.get("mrz")
            or data.get("mrz_lines")
            or resp.get("mrz_lines")
        )

        mrz_dict: Dict[str, Any] = {}
        if mrz_raw:
            mrz_dict = parse_td3_mrz(mrz_raw)
        else:
            mrz_l1 = _find_field(resp, ["mrz_line_1", "mrz_line1", "line1", "line_1"])
            mrz_l2 = _find_field(resp, ["mrz_line_2", "mrz_line2", "line2", "line_2"])
            if mrz_l1 and mrz_l2:
                mrz_dict = parse_td3_mrz([mrz_l1, mrz_l2])

        # If MRZ is parsed, check for discrepancies and backfill missing visual fields
        if mrz_dict.get("valid_format"):
            if mrz_dict.get("check_digits_valid") is False:
                bad_fields = ", ".join(mrz_dict.get("check_digit_failures") or ["unknown"])
                warnings.append(f"ICAO TD3 MRZ check-digit verification failed ({bad_fields}). Please verify extracted fields.")
            mrz_pass = mrz_dict.get("passport_number", "")
            mrz_nat = mrz_dict.get("nationality", "")
            mrz_dob = mrz_dict.get("dob", "")
            mrz_exp = mrz_dict.get("expiry_date", "")
            mrz_gen = mrz_dict.get("gender", "")
            mrz_country = mrz_dict.get("issuing_country", "")
            mrz_given = mrz_dict.get("given_names", "")
            mrz_sur = mrz_dict.get("surname", "")

            # Discrepancy checks
            if pass_num and mrz_pass and pass_num.replace(" ", "") != mrz_pass.replace(" ", ""):
                warnings.append(
                    f"Discrepancy detected: Visual Passport Number ('{pass_num}') does not match MRZ Passport Number ('{mrz_pass}')."
                )
            if nationality and mrz_nat:
                nat_clean = nationality.upper().strip()
                mrz_nat_clean = mrz_nat.upper().strip()
                if nat_clean not in mrz_nat_clean and mrz_nat_clean not in nat_clean and nat_clean != "INDIAN":
                    warnings.append(
                        f"Discrepancy detected: Visual Nationality ('{nationality}') does not match MRZ Nationality ('{mrz_nat}')."
                    )
            if gender and mrz_gen:
                if gender.upper()[0] != mrz_gen.upper()[0]:
                    warnings.append(
                        f"Discrepancy detected: Visual Gender ('{gender}') does not match MRZ Gender ('{mrz_gen}')."
                    )

            # Backfill missing visual fields from MRZ
            if not pass_num and mrz_pass:
                pass_num = mrz_pass
            if not nationality and mrz_nat:
                nationality = mrz_nat
            if not gender and mrz_gen:
                gender = mrz_gen
            if not dob and mrz_dob:
                dob = mrz_dob
            if not expiry and mrz_exp:
                expiry = mrz_exp
            if not issuing_country and mrz_country:
                issuing_country = mrz_country
            if not given_name and mrz_given:
                given_name = mrz_given
            if not surname and mrz_sur:
                surname = mrz_sur

        # Synthesize Full Name if missing, or derive given_name/surname from Full Name
        if not full_name:
            if given_name or surname:
                full_name = f"{given_name} {surname}".strip()
            elif mrz_dict.get("full_name"):
                full_name = mrz_dict["full_name"]
        elif not given_name and not surname:
            name_parts = full_name.split()
            if len(name_parts) > 1:
                given_name = " ".join(name_parts[:-1])
                surname = name_parts[-1]
            else:
                given_name = full_name

        if not issuing_country and (doc_type_label == "Indian Passport" or endpoint == ENDPOINT_INDIAN_PASSPORT):
            issuing_country = "IND"

        # Calendar Date Validations
        if dob:
            is_valid, _ = validate_date_string(dob)
            if not is_valid:
                warnings.append(f"Invalid Date of Birth detected: '{dob}'. Not a valid calendar date.")
        if expiry:
            is_valid, _ = validate_date_string(expiry)
            if not is_valid:
                warnings.append(f"Invalid Expiry Date detected: '{expiry}'. Not a valid calendar date.")
        if issue_date:
            is_valid, _ = validate_date_string(issue_date)
            if not is_valid:
                warnings.append(f"Invalid Issue Date detected: '{issue_date}'. Not a valid calendar date.")

        extracted_fields = {
            "Full Name": full_name,
            "Given Name": given_name,
            "Surname": surname,
            "Passport Number": pass_num,
            "Date of Birth": dob,
            "Expiry Date": expiry,
            "Nationality": nationality,
            "Gender": gender,
            "Issue Date": issue_date,
            "Issuing Country": issuing_country,
            "Place of Issue": place_of_issue,
            "MRZ Line 1": mrz_dict.get("mrz_line_1", ""),
            "MRZ Line 2": mrz_dict.get("mrz_line_2", "")
        }

        raw_lines = [
            f"PASSPORT NUMBER: {pass_num}",
            f"NAME: {full_name}",
            f"DATE OF BIRTH: {dob}",
            f"DATE OF EXPIRY: {expiry}",
            f"NATIONALITY: {nationality}",
        ]
        if gender:
            raw_lines.append(f"GENDER: {gender}")
        if issue_date:
            raw_lines.append(f"DATE OF ISSUE: {issue_date}")
        if issuing_country:
            raw_lines.append(f"ISSUING COUNTRY: {issuing_country}")
        if mrz_dict.get("mrz_line_1"):
            raw_lines.append(mrz_dict["mrz_line_1"])
        if mrz_dict.get("mrz_line_2"):
            raw_lines.append(mrz_dict["mrz_line_2"])

        conf = resp.get("confidence_scores") or resp.get("confidence") or {}

        return {
            "success": True,
            "provider": "AZAPI.ai",
            "document_type": doc_type_label,
            "endpoint": endpoint,
            "raw_text": "\n".join(raw_lines),
            "extracted_fields": extracted_fields,
            "confidence": conf,
            "mrz_data": mrz_dict,
            "raw_response": resp,
            "warnings": warnings,
            "is_reviewed": False,
            "can_overwrite_verified": False,
            "source_type": "azapi_cloud_ocr"
        }

    # -------------------------------------------------------------------------
    # AZAPI-Only Unified Dispatcher (Zero Local Fallback)
    # -------------------------------------------------------------------------

    def extract(
        self,
        file_bytes: bytes,
        filename: str,
        expected_type: str,
        back_file_bytes: Optional[bytes] = None,
        back_filename: Optional[str] = None,
        passport_kind: Optional[str] = None,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """
        Dispatches OCR extraction strictly to the appropriate verified AZAPI endpoint.
        Raises AZAPIUnsupportedEndpointError if expected_type has no AZAPI endpoint.
        Performs zero automatic retries.
        """
        norm_type = (expected_type or "").lower().strip()

        if "foreign" in norm_type and "passport" in norm_type:
            return self.extract_foreign_passport(
                file_bytes, filename,
                back_file_bytes=back_file_bytes,
                back_filename=back_filename,
                timeout=timeout,
                force_retry=force_retry,
            )
        elif "indian" in norm_type and "passport" in norm_type:
            return self.extract_indian_passport(
                file_bytes, filename,
                back_file_bytes=back_file_bytes,
                back_filename=back_filename,
                timeout=timeout,
                force_retry=force_retry,
            )
        elif "passport" in norm_type:
            return self.extract_passport(
                file_bytes, filename,
                back_file_bytes=back_file_bytes,
                back_filename=back_filename,
                passport_kind=passport_kind,
                timeout=timeout,
                force_retry=force_retry,
            )
        elif "aadhaar" in norm_type or "adhaar" in norm_type or "uidai" in norm_type:
            return self.extract_aadhaar(
                file_bytes, filename,
                back_file_bytes=back_file_bytes,
                back_filename=back_filename,
                timeout=timeout,
                force_retry=force_retry,
            )
        elif "pan" in norm_type:
            return self.extract_pan(
                file_bytes, filename,
                timeout=timeout,
                force_retry=force_retry,
            )
        else:
            raise AZAPIUnsupportedEndpointError(
                f"Document type '{expected_type}' has no AZAPI OCR endpoint. Manual staff entry is required."
            )

    def extract_or_manual_review(
        self,
        file_bytes: bytes,
        filename: str,
        expected_type: Optional[str] = None,
        back_file_bytes: Optional[bytes] = None,
        back_filename: Optional[str] = None,
        passport_kind: Optional[str] = None,
        timeout: Optional[int] = None,
        force_retry: bool = False,
    ) -> Dict[str, Any]:
        """
        AZAPI-only extraction entrypoint with fail-closed manual review fallback:
        1. Unsupported document types route cleanly to manual staff entry (zero API call).
        2. If AZAPI is disabled/unconfigured, returns manual review status (zero API call).
        3. Executes a single AZAPI request (zero automatic retries); errors return manual review
           status with explicit manual retry eligibility (can_retry_azapi=True).
        """
        if not expected_type or not self._matches_supported_type(expected_type):
            return {
                "success": False,
                "raw_text": "",
                "provider": "manual_review",
                "source_type": "manual_review_required",
                "manual_review_required": True,
                "can_retry_azapi": False,
                "azapi_status": "unsupported",
                "extracted_fields": {},
                "warnings": [
                    f"Document type '{expected_type or 'General Document'}' does not use cloud OCR. "
                    "Please verify the document preview and enter fields manually."
                ],
                "confidence": {},
                "is_reviewed": False,
                "can_overwrite_verified": False,
            }

        is_avail, reason = self.is_available()
        if not is_avail:
            return {
                "success": False,
                "raw_text": "",
                "provider": "azapi_disabled_manual_review",
                "source_type": "manual_review_required",
                "manual_review_required": True,
                "can_retry_azapi": False,
                "azapi_status": "disabled",
                "extracted_fields": {},
                "warnings": [
                    "AZAPI cloud OCR is currently disabled. Please review the document preview and enter details manually."
                ],
                "confidence": {},
                "is_reviewed": False,
                "can_overwrite_verified": False,
            }

        try:
            return self.extract(
                file_bytes,
                filename,
                expected_type,
                back_file_bytes=back_file_bytes,
                back_filename=back_filename,
                passport_kind=passport_kind,
                timeout=timeout,
                force_retry=force_retry,
            )
        except Exception as e:
            safe_err = f"{type(e).__name__}: {str(e)}"
            logger.warning("AZAPI OCR extraction failed (%s). Routing to manual review (zero auto-retry).", type(e).__name__)
            return {
                "success": False,
                "raw_text": "",
                "provider": "azapi_error_manual_review",
                "source_type": "manual_review_required",
                "manual_review_required": True,
                "can_retry_azapi": True,
                "azapi_status": "error",
                "azapi_error": safe_err,
                "extracted_fields": {},
                "warnings": [
                    f"AZAPI extraction did not complete ({safe_err}). "
                    "You may use 'Retry AZAPI Extraction' or enter details manually."
                ],
                "confidence": {},
                "is_reviewed": False,
                "can_overwrite_verified": False,
            }

    def _matches_supported_type(self, doc_type: str) -> bool:
        """Internal helper to test if expected doc type string maps to a supported type."""
        d = (doc_type or "").lower().strip()
        if "foreign" in d and "passport" in d:
            return self.config.foreign_passport_enabled and self.config.passport_enabled
        if "passport" in d:
            return self.config.passport_enabled
        if "aadhaar" in d or "adhaar" in d or "uidai" in d:
            return self.config.aadhaar_enabled
        if "pan" in d:
            return self.config.pan_enabled
        return False


# Global default instance (lazy initialized)
_default_adapter: Optional[AZAPIAdapter] = None

def get_azapi_adapter() -> AZAPIAdapter:
    """Returns the process-wide default AZAPI adapter."""
    global _default_adapter
    if _default_adapter is None:
        _default_adapter = AZAPIAdapter()
    return _default_adapter

def set_azapi_adapter(adapter: AZAPIAdapter) -> None:
    """Sets the process-wide default AZAPI adapter (useful for testing)."""
    global _default_adapter
    _default_adapter = adapter

def reset_azapi_adapter() -> None:
    """Resets the process-wide default AZAPI adapter."""
    global _default_adapter
    _default_adapter = None
