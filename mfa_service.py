"""
Khanna Travels - KT Vault V3
Multi-Factor Authentication (MFA) Core Service (mfa_service.py)
Phase 5A: RFC 6238 TOTP Engine, AES-256-GCM Encrypted Secret Storage, Replay Protection & Rate Limiting

Security Properties:
1. Standard TOTP (RFC 6238):
   - 30-second time interval.
   - 6-digit one-time passcode.
   - HMAC-SHA1 digest with standard 160-bit (32 base32 characters) entropy.
   - Drift window of +/- 1 time-step (30s) to absorb legitimate mobile device clock skew.
2. Encryption at Rest (NIST SP 800-38D AES-256-GCM):
   - TOTP secrets are encrypted at rest using the active vault key provider (Windows DPAPI / ktv_2026_v1).
   - Additional Authenticated Data (AAD) binds the ciphertext strictly to the specific user ID:
     AAD = b"KTV_MFA_SECRET|user_id:" + user_id.encode('utf-8')
   - Prevents ciphertext substitution attacks between accounts.
3. Replay Protection:
   - Tracks the integer time-step index of the last accepted code in `mfa_last_used_step`.
   - Rejects any code submitted for a time-step <= `mfa_last_used_step`, strictly blocking
     token replay within the same or earlier 30-second window.
4. Rate Limiting & Account Lockout:
   - Maximum 5 consecutive failed MFA attempts before triggering a 15-minute lockout.
5. In-Memory QR Generation:
   - QR code PNG bytes and otpauth:// provisioning URIs are generated strictly in RAM.
   - Never written to disk, stdout, or plaintext log files.
6. Single-Use Emergency Recovery Codes:
   - 8 cryptographically secure single-use recovery codes.
   - Stored as SHA-256 hashes in database; consumed upon first use.
"""

import os
import io
import re
import json
import time
import base64
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple

import pyotp
import qrcode
from qrcode.image.pil import PilImage

import database
import storage_service

# Constants
TOTP_INTERVAL = 30
TOTP_DIGITS = 6
TOTP_VALID_WINDOW = 1  # +/- 1 step (30s)
MFA_MAX_FAILED_ATTEMPTS = 5
MFA_LOCKOUT_MINUTES = 15
MFA_LOGIN_LIFETIME_MINUTES = 5          # Strict short-lived for recurring login challenges
MFA_ENROLLMENT_LIFETIME_MINUTES = 15     # 15 minutes for comfortable first-time phone setup
PENDING_MFA_LIFETIME_MINUTES = MFA_LOGIN_LIFETIME_MINUTES  # Legacy alias
RECOVERY_CODE_COUNT = 8

MFA_ENVELOPE_PREFIX = b"KTV_MFA:v1:"
NONCE_BYTES = 12
TAG_BYTES = 16


# =====================================================================
# Database Schema Initialization
# =====================================================================

_INITIALIZED_MFA_DBS = set()


def _conn_db_key(conn) -> str:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
        if row and len(row) >= 3 and row[2]:
            return os.path.abspath(row[2])
    except Exception:
        pass
    return os.path.abspath(database.get_db_path())


def ensure_mfa_schema(conn=None) -> None:
    """Lazily ensures MFA columns and tables on the active DB path without running at module import."""
    target_key = _conn_db_key(conn) if conn is not None else os.path.abspath(database.get_db_path())
    if target_key in _INITIALIZED_MFA_DBS:
        return
    init_mfa_schema(conn)
    _INITIALIZED_MFA_DBS.add(target_key)


def init_mfa_schema(conn=None) -> None:
    """
    Safely and idempotently adds MFA columns to users table and creates
    the pending_mfa_sessions table.
    """
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True

    try:
        c = conn.cursor()

        # Safely add MFA columns to users table
        mfa_user_columns = [
            ("mfa_secret", "TEXT DEFAULT NULL"),
            ("mfa_enrolled_at", "TEXT DEFAULT NULL"),
            ("mfa_last_used_step", "INTEGER DEFAULT 0"),
            ("mfa_failed_attempts", "INTEGER DEFAULT 0"),
            ("mfa_locked_until", "TEXT DEFAULT NULL"),
            ("mfa_recovery_hashes", "TEXT DEFAULT NULL"),
        ]
        for col_name, col_def in mfa_user_columns:
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass  # Column already exists

        # Table for ephemeral pending MFA login/enrollment sessions
        c.execute("""
            CREATE TABLE IF NOT EXISTS pending_mfa_sessions (
                temp_token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                session_type TEXT NOT NULL,
                pending_secret TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                ip_address TEXT,
                attempts INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_pending_mfa_user ON pending_mfa_sessions(user_id)")
        conn.commit()
        _INITIALIZED_MFA_DBS.add(_conn_db_key(conn))
    finally:
        if should_close:
            conn.close()


# =====================================================================
# Cryptographic Storage Helpers (AES-256-GCM with DPAPI/Master Key)
# =====================================================================

def _get_encryption_key() -> bytes:
    """
    Retrieves the 32-byte master encryption key from the active KeyProvider.
    Prefers 'ktv_2026_v1', falling back to 'master'.
    """
    prov = storage_service.get_key_provider()
    if prov.has_key("ktv_2026_v1"):
        return prov.get_key("ktv_2026_v1")
    elif prov.has_key("master"):
        return prov.get_key("master")
    else:
        # Fallback check for any available key
        keys = getattr(prov, "list_keys", lambda: [])()
        if keys:
            return prov.get_key(keys[0])
        raise RuntimeError("MFA secret encryption blocked: No encryption key available from KeyProvider.")


def encrypt_totp_secret(secret_base32: str, user_id: str) -> str:
    """
    Encrypts a base32 TOTP secret using AES-256-GCM.
    Binds ciphertext strictly to user_id via AAD.
    Returns serialized envelope string: 'KTV_MFA:v1:<base64>'.
    """
    if not secret_base32 or not isinstance(secret_base32, str):
        raise ValueError("Invalid secret to encrypt.")
    if not user_id or not isinstance(user_id, str):
        raise ValueError("user_id is required for AAD binding.")

    key = _get_encryption_key()
    cipher = storage_service.AES256GCMCipher(key)

    nonce = secrets.token_bytes(NONCE_BYTES)
    aad = f"KTV_MFA_SECRET|user_id:{user_id.strip()}".encode("utf-8")
    plaintext = secret_base32.strip().encode("utf-8")

    ciphertext, tag = cipher.encrypt(nonce, plaintext, aad)
    payload = nonce + tag + ciphertext
    b64_payload = base64.b64encode(payload).decode("ascii")

    return (MFA_ENVELOPE_PREFIX.decode("ascii") + b64_payload)


def decrypt_totp_secret(encrypted_envelope: str, user_id: str) -> str:
    """
    Decrypts an AES-256-GCM encrypted TOTP secret envelope.
    Verifies AAD matching user_id.
    Raises ValueError on tampering, corruption, or authentication tag mismatch.
    """
    if not encrypted_envelope or not isinstance(encrypted_envelope, str):
        raise ValueError("Invalid encrypted envelope.")
    if not user_id or not isinstance(user_id, str):
        raise ValueError("user_id is required for AAD verification.")

    prefix = MFA_ENVELOPE_PREFIX.decode("ascii")
    if not encrypted_envelope.startswith(prefix):
        raise ValueError("Unrecognized MFA envelope header format.")

    b64_payload = encrypted_envelope[len(prefix):]
    try:
        payload = base64.b64decode(b64_payload.encode("ascii"))
    except Exception as e:
        raise ValueError(f"Failed to decode base64 MFA envelope: {e}")

    if len(payload) < NONCE_BYTES + TAG_BYTES:
        raise ValueError("MFA envelope payload is truncated.")

    nonce = payload[:NONCE_BYTES]
    tag = payload[NONCE_BYTES:NONCE_BYTES + TAG_BYTES]
    ciphertext = payload[NONCE_BYTES + TAG_BYTES:]

    key = _get_encryption_key()
    cipher = storage_service.AES256GCMCipher(key)
    aad = f"KTV_MFA_SECRET|user_id:{user_id.strip()}".encode("utf-8")

    try:
        plaintext = cipher.decrypt(nonce, tag, ciphertext, aad)
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"MFA secret decryption failed (tampered or wrong key): {e}")


# =====================================================================
# Secret Generation, QR Codes, and Recovery Codes
# =====================================================================

def generate_totp_secret() -> str:
    """
    Generates a cryptographically secure 160-bit (32 character) base32 secret.
    """
    return pyotp.random_base32()


def get_provisioning_uri(secret_base32: str, username: str, issuer: str = "Khanna Travels Vault") -> str:
    """
    Generates standard otpauth:// URI for authenticator applications.
    """
    totp = pyotp.TOTP(secret_base32, interval=TOTP_INTERVAL, digits=TOTP_DIGITS)
    return totp.provisioning_uri(name=username.strip(), issuer_name=issuer.strip())


def generate_qr_code_png(provisioning_uri: str) -> bytes:
    """
    Generates in-memory PNG image bytes of the QR code.
    Never writes to disk.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#0B2348", back_color="#FFFFFF")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> Tuple[List[str], str]:
    """
    Generates a list of single-use plaintext recovery codes and their serialized SHA-256 hashes.
    Returns (plaintext_codes_list, json_hashes_string).
    Format of each code: KTV-XXXX-XXXX-XXXX
    """
    plaintext_codes = []
    hashes = []
    for _ in range(count):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        part3 = secrets.token_hex(2).upper()
        code = f"KTV-{part1}-{part2}-{part3}"
        plaintext_codes.append(code)
        norm = normalize_code(code)
        h = hashlib.sha256(norm.encode("utf-8")).hexdigest()
        hashes.append(h)

    return plaintext_codes, json.dumps(hashes)


def normalize_code(code: str) -> str:
    """Normalizes code by removing spaces, dashes, and converting to uppercase."""
    return re.sub(r"[\s\-]", "", str(code)).strip().upper()


# =====================================================================
# TOTP Verification & Replay Protection
# =====================================================================

def verify_totp_code(
    secret_base32: str,
    code: str,
    last_used_step: int = 0
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Verifies a 6-digit TOTP code against a base32 secret.
    Enforces replay protection against `last_used_step`.

    Returns:
        (is_valid, matched_step, error_message)
    """
    clean_code = re.sub(r"[\s\-]", "", str(code)).strip()
    if not re.match(r"^\d{6}$", clean_code):
        return False, None, "Code must be exactly 6 numeric digits."

    totp = pyotp.TOTP(secret_base32, interval=TOTP_INTERVAL, digits=TOTP_DIGITS)
    current_time = time.time()
    current_step = int(current_time / TOTP_INTERVAL)

    # Check candidates within valid window (+/- 1 step)
    matched_step = None
    for step_offset in (0, -1, 1):
        test_step = current_step + step_offset
        expected_code = totp.at(test_step * TOTP_INTERVAL)
        if secrets.compare_digest(clean_code, expected_code):
            matched_step = test_step
            break

    if matched_step is None:
        return (
            False,
            None,
            "Invalid or mismatched code: The 6-digit code did not match. Please ensure you are reading the latest code for 'Khanna Travels Vault' from your authenticator app before the 30-second timer expires. If you have an older entry in your app, click 'Start Fresh / Regenerate QR Code' to reset."
        )

    # Replay Protection: step must be strictly greater than last used step
    if matched_step <= (last_used_step or 0):
        return (
            False,
            None,
            "Replay detected: this one-time code was already used. Please wait for your authenticator app to display the next code."
        )

    return True, matched_step, None


# =====================================================================
# Ephemeral Pending MFA Session Management
# =====================================================================

def get_active_pending_enrollment(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Checks if there is an active, unexpired pending ENROLLMENT session for user_id.
    Returns the session dict if valid, or None if expired or nonexistent.
    If expired, purges it from the database immediately.
    """
    if not user_id or not isinstance(user_id, str):
        return None
    ensure_mfa_schema()
    conn = database.get_connection()
    try:
        row = conn.execute("""
            SELECT temp_token, user_id, session_type, pending_secret, created_at, expires_at, ip_address, attempts
            FROM pending_mfa_sessions
            WHERE user_id = ? AND session_type = 'ENROLLMENT'
        """, (user_id.strip(),)).fetchone()
        if not row:
            return None
        d = dict(row)
        expires_at = datetime.fromisoformat(d["expires_at"])
        if datetime.now() > expires_at:
            conn.execute("DELETE FROM pending_mfa_sessions WHERE temp_token = ?", (d["temp_token"],))
            conn.commit()
            return None
        return d
    finally:
        conn.close()


def create_pending_mfa_session(
    user_id: str,
    session_type: str,
    pending_secret: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    reuse_existing_enrollment: bool = False
) -> str:
    """
    Creates or reuses an ephemeral pending MFA session.
    - ENROLLMENT lifetime: 15 minutes.
    - LOGIN challenge lifetime: 5 minutes.
    If reuse_existing_enrollment is True and a valid unexpired ENROLLMENT session exists,
    returns its existing temp_token without modifying the secret or QR code.
    """
    init_mfa_schema()
    conn = database.get_connection()
    try:
        if reuse_existing_enrollment and session_type == "ENROLLMENT":
            existing = get_active_pending_enrollment(user_id)
            if existing and existing.get("pending_secret"):
                return existing["temp_token"]

        # Purge any existing pending sessions for this user
        conn.execute("DELETE FROM pending_mfa_sessions WHERE user_id = ?", (user_id,))

        temp_token = "MFA_PENDING_" + secrets.token_urlsafe(32)
        lifetime = MFA_ENROLLMENT_LIFETIME_MINUTES if session_type == "ENROLLMENT" else MFA_LOGIN_LIFETIME_MINUTES
        now_dt = datetime.now()
        created_at = now_dt.isoformat()
        expires_at = (now_dt + timedelta(minutes=lifetime)).isoformat()

        conn.execute("""
            INSERT INTO pending_mfa_sessions (temp_token, user_id, session_type, pending_secret, created_at, expires_at, ip_address, attempts)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """, (temp_token, user_id, session_type, pending_secret, created_at, expires_at, ip_address))
        conn.commit()
        return temp_token
    finally:
        conn.close()


def get_pending_mfa_session(temp_token: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves and validates an ephemeral pending MFA session.
    Deletes expired sessions immediately.
    """
    if not temp_token or not isinstance(temp_token, str):
        return None

    ensure_mfa_schema()
    conn = database.get_connection()
    try:
        row = conn.execute("""
            SELECT temp_token, user_id, session_type, pending_secret, created_at, expires_at, ip_address, attempts
            FROM pending_mfa_sessions
            WHERE temp_token = ?
        """, (temp_token.strip(),)).fetchone()

        if not row:
            return None

        d = dict(row)
        expires_at = datetime.fromisoformat(d["expires_at"])
        if datetime.now() > expires_at:
            conn.execute("DELETE FROM pending_mfa_sessions WHERE temp_token = ?", (temp_token,))
            conn.commit()
            return None

        return d
    finally:
        conn.close()


def increment_pending_session_attempts(temp_token: str) -> int:
    """Increments failed attempt count on the pending session."""
    conn = database.get_connection()
    try:
        conn.execute("UPDATE pending_mfa_sessions SET attempts = attempts + 1 WHERE temp_token = ?", (temp_token,))
        conn.commit()
        row = conn.execute("SELECT attempts FROM pending_mfa_sessions WHERE temp_token = ?", (temp_token,)).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def delete_pending_mfa_session(temp_token: str) -> None:
    """Removes a completed or terminated pending MFA session."""
    if not temp_token:
        return
    conn = database.get_connection()
    try:
        conn.execute("DELETE FROM pending_mfa_sessions WHERE temp_token = ?", (temp_token.strip(),))
        conn.commit()
    finally:
        conn.close()


# =====================================================================
# Rate Limiting & Account Lockout Enforcement
# =====================================================================

def check_mfa_lockout(user_dict: Dict[str, Any]) -> None:
    """
    Checks whether a user's MFA is currently locked out.
    Raises PermissionError if locked.
    """
    locked_until_str = user_dict.get("mfa_locked_until")
    if locked_until_str:
        try:
            locked_until_dt = datetime.fromisoformat(locked_until_str)
            if datetime.now() < locked_until_dt:
                rem_min = int((locked_until_dt - datetime.now()).total_seconds() / 60) + 1
                raise PermissionError(
                    f"MFA verification temporarily locked due to {MFA_MAX_FAILED_ATTEMPTS} consecutive failed attempts. "
                    f"Please try again in {rem_min} minute(s) or contact your administrator."
                )
            else:
                # Lockout expired, clear it
                clear_mfa_failed_attempts(user_dict["id"])
        except ValueError:
            pass


def record_mfa_failed_attempt(user_id: str, ip_address: str = "127.0.0.1") -> int:
    """
    Increments mfa_failed_attempts on user record.
    If >= MFA_MAX_FAILED_ATTEMPTS, sets mfa_locked_until to +15 minutes.
    Returns new attempt count.
    """
    conn = database.get_connection()
    try:
        row = conn.execute("SELECT COALESCE(mfa_failed_attempts, 0) FROM users WHERE id = ?", (user_id,)).fetchone()
        attempts = (row[0] if row else 0) + 1

        locked_val = None
        if attempts >= MFA_MAX_FAILED_ATTEMPTS:
            locked_val = (datetime.now() + timedelta(minutes=MFA_LOCKOUT_MINUTES)).isoformat()

        conn.execute("""
            UPDATE users SET mfa_failed_attempts = ?, mfa_locked_until = ? WHERE id = ?
        """, (attempts, locked_val, user_id))
        conn.commit()
        return attempts
    finally:
        conn.close()


def clear_mfa_failed_attempts(user_id: str) -> None:
    """Resets mfa_failed_attempts and mfa_locked_until upon successful verification."""
    conn = database.get_connection()
    try:
        conn.execute("UPDATE users SET mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


# =====================================================================
# Single-Use Recovery Code Verification
# =====================================================================

def verify_and_consume_recovery_code(user_id: str, input_code: str) -> bool:
    """
    Verifies an emergency recovery code against user's stored SHA-256 hashes.
    If valid, consumes the code (deletes it from the stored list).
    Returns True if valid, False otherwise.
    """
    if not input_code or not user_id:
        return False

    ensure_mfa_schema()
    norm = normalize_code(input_code)
    h_input = hashlib.sha256(norm.encode("utf-8")).hexdigest()

    conn = database.get_connection()
    try:
        row = conn.execute("SELECT mfa_recovery_hashes FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row or not row[0]:
            return False

        try:
            hashes = json.loads(row[0])
            if not isinstance(hashes, list):
                return False
        except Exception:
            return False

        matched_idx = -1
        for i, h in enumerate(hashes):
            if secrets.compare_digest(h_input, h):
                matched_idx = i
                break

        if matched_idx == -1:
            return False

        # Consume the code
        hashes.pop(matched_idx)
        conn.execute("UPDATE users SET mfa_recovery_hashes = ? WHERE id = ?", (json.dumps(hashes), user_id))
        conn.commit()
        return True
    finally:
        conn.close()
