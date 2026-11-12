"""
Khanna Travels - KT Vault V3
Authentication, Identity and Granular Access Control Service (auth_services.py)
Phase 16 Hardening: Multi-role RBAC, Account Lockout, Session Fixation Protection & SSO/MFA Adapters
"""

import sqlite3
import json
import hashlib
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set, Tuple
import database
import mfa_service

logger = logging.getLogger("kt_vault.auth")
_AUTH_AUDIT_LOCK = threading.Lock()
_INITIALIZED_AUTH_DBS: Set[str] = set()

DEFAULT_IDLE_TIMEOUT_MINUTES = 30
DEFAULT_SESSION_MAX_HOURS = 12


def get_idle_timeout_minutes() -> int:
    try:
        val = int(os.environ.get("KT_SESSION_IDLE_TIMEOUT_MINUTES", str(DEFAULT_IDLE_TIMEOUT_MINUTES)))
        return max(1, val)
    except (ValueError, TypeError):
        return DEFAULT_IDLE_TIMEOUT_MINUTES


def get_max_session_hours() -> int:
    try:
        val = int(os.environ.get("KT_SESSION_MAX_HOURS", str(DEFAULT_SESSION_MAX_HOURS)))
        return max(1, val)
    except (ValueError, TypeError):
        return DEFAULT_SESSION_MAX_HOURS


def _auth_conn_db_key(conn) -> str:
    try:
        row = conn.execute("PRAGMA database_list").fetchone()
        if row and len(row) >= 3 and row[2]:
            return os.path.abspath(row[2])
    except Exception:
        pass
    return os.path.abspath(database.get_db_path())


def ensure_auth_schema(conn=None):
    """Lazily ensures auth & security audit schemas on active DB without import-time DB I/O."""
    db_key = _auth_conn_db_key(conn) if conn is not None else os.path.abspath(database.get_db_path())
    if db_key in _INITIALIZED_AUTH_DBS:
        return
    init_auth_schema(conn)
    _INITIALIZED_AUTH_DBS.add(db_key)


def _create_session_record(conn, user_id: str) -> Tuple[str, str]:
    """Creates an authenticated session enforcing fixation purge and 30-min idle timeout."""
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    token = secrets.token_urlsafe(32)
    now_dt = datetime.now()
    idle_expires = (now_dt + timedelta(minutes=get_idle_timeout_minutes())).isoformat()
    created_iso = now_dt.isoformat()
    try:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, created_iso, idle_expires),
        )
    except sqlite3.OperationalError:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, idle_expires),
        )
    return token, idle_expires


# =====================================================================
# Database Migration & Schema Initialization
# =====================================================================

def init_auth_schema(conn=None):
    """
    Safely ensures that all Phase 16 authentication, RBAC, and security
    audit columns and tables exist in the SQLite database.
    Idempotent and non-destructive.
    """
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True

    try:
        c = conn.cursor()
        # Add columns to users table safely
        columns = [
            ("is_active", "INTEGER DEFAULT 1"),
            ("department", "TEXT DEFAULT 'General'"),
            ("failed_attempts", "INTEGER DEFAULT 0"),
            ("locked_until", "TEXT DEFAULT NULL"),
            ("mfa_enabled", "INTEGER DEFAULT 0"),
            ("auth_provider", "TEXT DEFAULT 'local'")
        ]
        for col_name, col_def in columns:
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
            except sqlite3.OperationalError:
                pass  # Already exists

        # Create security audit log table
        c.execute("""
            CREATE TABLE IF NOT EXISTS security_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                username TEXT,
                user_id TEXT,
                role TEXT,
                ip_address TEXT,
                details TEXT,
                previous_event_hash TEXT,
                event_hash TEXT
            )
        """)
        for audit_col, audit_def in [("previous_event_hash", "TEXT"), ("event_hash", "TEXT")]:
            try:
                c.execute(f"ALTER TABLE security_audit_logs ADD COLUMN {audit_col} {audit_def}")
            except sqlite3.OperationalError:
                pass
        try:
            mfa_service.init_mfa_schema(conn)
        except Exception:
            pass
        conn.commit()
        _INITIALIZED_AUTH_DBS.add(_auth_conn_db_key(conn))
    finally:
        if should_close:
            conn.close()


# =====================================================================
# Security Audit Logging
# =====================================================================

def log_security_event(
    event_type: str,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    role: Optional[str] = None,
    details: Optional[str] = None,
    ip_address: str = "127.0.0.1",
    conn: Optional[Any] = None
):
    """
    Records security-relevant events to the durable security_audit_logs table.
    Enforces tamper-evident SHA-256 hash chaining (previous_event_hash + event_hash).
    Never records passwords, tokens, full Aadhaar/PAN, or encryption keys.
    """
    if conn is None:
        ensure_auth_schema()
    with _AUTH_AUDIT_LOCK:
        should_close = False
        if conn is None:
            conn = database.get_connection()
            should_close = True

        try:
            if should_close and not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            now_iso = datetime.now().isoformat()

            last_row = conn.execute(
                "SELECT event_hash FROM security_audit_logs WHERE event_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = last_row['event_hash'] if last_row and last_row['event_hash'] else "GENESIS_HASH"

            canonical_payload = f"{now_iso}|{str(event_type)}|{user_id or ''}|{username or ''}|{role or ''}|{ip_address or ''}|{details or ''}"
            event_hash = hashlib.sha256(f"{canonical_payload}|{prev_hash}".encode('utf-8')).hexdigest()

            conn.execute(
                """
                INSERT INTO security_audit_logs (event_type, username, user_id, role, ip_address, details, timestamp, previous_event_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event_type),
                    username,
                    user_id,
                    role,
                    ip_address,
                    details,
                    now_iso,
                    prev_hash,
                    event_hash
                )
            )
            if should_close:
                conn.commit()
        except Exception as audit_err:
            if should_close and conn.in_transaction:
                try:
                    conn.rollback()
                except Exception:
                    pass
            logger.error("Failed to record security audit event '%s': %s", event_type, audit_err)
        finally:
            if should_close:
                conn.close()

def verify_audit_log_integrity(conn: Optional[Any] = None) -> Tuple[bool, int, Optional[str]]:
    """
    Verifies the cryptographic tamper-evident hash chain across all security_audit_logs entries.
    Returns (is_valid, checked_count, error_details).
    """
    should_close = False
    if conn is None:
        conn = database.get_connection()
        should_close = True

    try:
        rows = conn.execute(
            "SELECT id, timestamp, event_type, user_id, username, role, ip_address, details, previous_event_hash, event_hash FROM security_audit_logs WHERE event_hash IS NOT NULL ORDER BY id ASC"
        ).fetchall()

        if not rows:
            return True, 0, None

        expected_prev_hash = "GENESIS_HASH"
        checked_count = 0

        for r in rows:
            if r['previous_event_hash'] != expected_prev_hash:
                return False, checked_count, f"Hash chain break at log ID {r['id']}: expected prev_hash '{expected_prev_hash}', found '{r['previous_event_hash']}'"

            canonical_payload = f"{r['timestamp']}|{r['event_type']}|{r['user_id'] or ''}|{r['username'] or ''}|{r['role'] or ''}|{r['ip_address'] or ''}|{r['details'] or ''}"
            recomputed = hashlib.sha256(f"{canonical_payload}|{r['previous_event_hash']}".encode('utf-8')).hexdigest()

            if recomputed != r['event_hash']:
                return False, checked_count, f"Event hash mismatch at log ID {r['id']}: stored '{r['event_hash']}', recomputed '{recomputed}'"

            expected_prev_hash = r['event_hash']
            checked_count += 1

        return True, checked_count, None
    finally:
        if should_close:
            conn.close()


# =====================================================================
# Granular Role-Based Access Control (RBAC) Specification
# =====================================================================

# The four core office departments with shared document access:
OFFICE_DEPARTMENTS = {"Sales", "Visa", "Operations", "Ticketing"}

# Authorized reviewers permitted to verify or reject travel documents:
AUTHORIZED_REVIEWER_ROLES = {"Administrator", "Operations", "Visa", "Ticketing", "Supervisor", "Admin"}

# System administrators with authority over deletion, users, keys, and security:
ADMIN_ROLES = {"Administrator", "Admin"}

# All office personnel permitted general document read, preview, download, and upload:
ALL_OFFICE_ROLES = OFFICE_DEPARTMENTS | ADMIN_ROLES | {"Staff", "Supervisor"}

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "Administrator": {
        "customer:view", "customer:create", "customer:edit",
        "customer:archive", "customer:unarchive", "customer:delete", "customer:request_delete",
        "document:view_metadata", "document:view_content", "document:download",
        "document:upload", "document:verify", "document:reopen", "document:version_history", "document:delete",
        "document:archive", "document:restore", "document:replace", "document:request_delete",
        "admin:access", "admin:user_manage", "admin:key_rotate", "admin:backup",
        "audit:view", "audit:view_destructive", "trip:view", "trip:create", "trip:edit", "pack:generate"
    },
    "Operations": {
        "customer:view", "customer:create", "customer:edit",
        "customer:request_delete",
        "document:view_metadata", "document:view_content", "document:download",
        "document:upload", "document:verify", "document:reopen", "document:version_history",
        "document:archive", "document:restore", "document:replace", "document:request_delete",
        "audit:view_destructive", "trip:view", "trip:create", "trip:edit", "pack:generate"
    },
    "Visa": {
        "customer:view", "customer:create", "customer:edit",
        "customer:request_delete",
        "document:view_metadata", "document:view_content", "document:download",
        "document:upload", "document:verify", "document:reopen", "document:version_history",
        "document:archive", "document:restore", "document:replace", "document:request_delete",
        "trip:view", "trip:create", "trip:edit", "pack:generate"
    },
    "Ticketing": {
        "customer:view", "customer:create", "customer:edit",
        "customer:request_delete",
        "document:view_metadata", "document:view_content", "document:download",
        "document:upload", "document:verify", "document:reopen", "document:version_history",
        "document:archive", "document:restore", "document:replace", "document:request_delete",
        "trip:view", "trip:create", "trip:edit", "pack:generate"
    },
    "Sales": {
        "customer:view", "customer:create", "customer:edit",
        "customer:request_delete",
        "document:view_metadata", "document:view_content", "document:download",
        "document:upload", "document:version_history",
        "document:replace", "document:request_delete",
        "trip:view", "trip:create", "trip:edit", "pack:generate"
    },
    "Read-only Auditor": {
        "customer:view",
        "document:view_metadata", "document:view_content",
        "trip:view",
        "audit:view"
    }
}

# Role aliases for backward compatibility with existing V3 data
ROLE_ALIASES = {
    "Admin": "Administrator",
    "Supervisor": "Operations",
    "Staff": "Sales"
}

def normalize_role(role: str) -> str:
    """Resolves role aliases to canonical Phase 16 role names."""
    if not role:
        return "Unknown"
    role_str = str(role).strip()
    return ROLE_ALIASES.get(role_str, role_str)

def get_role_permissions(role: str) -> Set[str]:
    """Returns the set of permission codes granted to the role."""
    canonical = normalize_role(role)
    return ROLE_PERMISSIONS.get(canonical, set())

def has_permission(user_or_token: Any, permission_code: str) -> bool:
    """
    Checks if a user dict or session token has the requested permission.
    Returns False if unauthenticated, inactive, or unauthorized.
    """
    if isinstance(user_or_token, str):
        user = get_user_by_token(user_or_token)
    elif isinstance(user_or_token, dict):
        user = user_or_token
    else:
        return False

    if not user or user.get("is_active", 1) == 0:
        return False

    role = user.get("role", "")
    perms = get_role_permissions(role)
    return permission_code in perms

def require_permission(token: str, permission_code: str) -> Dict[str, Any]:
    """
    Enforces a granular permission on a session token.
    Raises PermissionError with clear security audit logging if denied.
    """
    user = get_user_by_token(token)
    if not user:
        log_security_event("PERMISSION_DENIED_UNAUTHENTICATED", details=f"Attempted {permission_code}")
        raise PermissionError("Unauthenticated: Invalid or expired session.")

    if user.get("is_active", 1) == 0:
        log_security_event("PERMISSION_DENIED_DISABLED", username=user.get("username"), details=f"Attempted {permission_code}")
        raise PermissionError("Unauthorized: Account has been deactivated.")

    role = user.get("role", "")
    perms = get_role_permissions(role)
    if permission_code not in perms:
        log_security_event(
            "PERMISSION_DENIED",
            username=user.get("username"),
            user_id=user.get("id"),
            role=role,
            details=f"Missing required permission: '{permission_code}'"
        )
        raise PermissionError(f"Unauthorized: Role '{role}' lacks permission '{permission_code}'.")

    return user

def can_access_document(role: str, department: str = "", doc_name_or_type: str = "", action: str = "view") -> bool:
    """
    Validates document access based on the confirmed Khanna Travels office workflow:
    1. The four departments — Sales, Visa, Operations and Ticketing — ALL have full shared access
       to search, view, preview, download, and upload all customer and trip documents.
    2. There are NO document-type visibility restrictions between these four departments.
       (e.g., Ticketing can view/download passports & visas; Visa can view/download flight tickets).
    3. Document verification and rejection strictly require an authorized reviewer role
       (Administrator, Operations, Visa, Ticketing). Sales and Read-only Auditor are rejected.
    4. Document deletion is strictly restricted to Administrator.
    5. Read-only Auditor is restricted to viewing metadata and previewing content for compliance.
    """
    canonical_role = normalize_role(role)
    dept = (department or "").strip()

    # 1. Document deletion: Strictly Administrator-controlled
    if action == "delete":
        return canonical_role in ADMIN_ROLES

    # 2. Document verification / rejection: Strictly Authorized Reviewer-controlled
    if action in ("verify", "reject", "reopen"):
        return canonical_role in AUTHORIZED_REVIEWER_ROLES

    # 3. Document view, preview, download, upload:
    # All 4 departments (Sales, Visa, Operations, Ticketing) + Administrator have full shared access
    # across ALL document types (passports, visas, flight tickets, hotel vouchers, itineraries, etc.)
    if (canonical_role in ADMIN_ROLES or
        canonical_role in OFFICE_DEPARTMENTS or
        dept in OFFICE_DEPARTMENTS or
        role in ("Staff", "Supervisor")):
        return True

    # 4. Read-only Auditor: View-only metadata and content preview for audit purposes
    if canonical_role == "Read-only Auditor":
        return action in ("view", "preview", "view_metadata")

    return False


# =====================================================================
# Identity & Authentication Adapters (SSO / MFA Architecture)
# =====================================================================

class IdentityAdapter:
    """
    Abstract identity adapter interface for enterprise authentication.
    Allows KT Vault to transition from local authentication to external SSO (e.g. Entra ID).
    """
    def authenticate(self, username: str, password: str, **kwargs) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def verify_mfa(self, user_id: str, mfa_token: str) -> bool:
        raise NotImplementedError

    def get_user_claims(self, user_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class LocalAuthAdapter(IdentityAdapter):
    """
    Local database authentication adapter using PBKDF2-HMAC-SHA256,
    salt per user, account lockout protection, and session fixation guards.
    """

    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15

    def authenticate(self, username: str, password: str, **kwargs) -> Optional[Dict[str, Any]]:
        ensure_auth_schema()
        conn = database.get_connection()
        ip_address = kwargs.get("ip_address", "127.0.0.1")
        totp_code = kwargs.get("totp_code")
        mfa_challenge_mode = kwargs.get("mfa_challenge_mode", False)
        try:
            user = conn.execute(
                """
                SELECT id, username, password_hash, salt, full_name, role,
                       COALESCE(is_active, 1) as is_active,
                       COALESCE(department, 'General') as department,
                       COALESCE(failed_attempts, 0) as failed_attempts,
                       locked_until,
                       COALESCE(mfa_enabled, 0) as mfa_enabled,
                       COALESCE(auth_provider, 'local') as auth_provider,
                       mfa_secret,
                       COALESCE(mfa_last_used_step, 0) as mfa_last_used_step,
                       COALESCE(mfa_failed_attempts, 0) as mfa_failed_attempts,
                       mfa_locked_until,
                       mfa_recovery_hashes
                FROM users WHERE username = ?
                """,
                (username,)
            ).fetchone()

            if not user:
                log_security_event("LOGIN_FAILED_UNKNOWN_USER", username=username, ip_address=ip_address)
                return None

            user_dict = dict(user)

            # 1. Check account active status
            if user_dict["is_active"] == 0:
                log_security_event(
                    "LOGIN_BLOCKED_DISABLED_ACCOUNT",
                    username=username,
                    user_id=user_dict["id"],
                    ip_address=ip_address
                )
                raise PermissionError("Account is disabled. Please contact the KT Vault administrator.")

            # 2. Check account lockout status
            locked_until_str = user_dict.get("locked_until")
            if locked_until_str:
                try:
                    locked_until_dt = datetime.fromisoformat(locked_until_str)
                    if datetime.now() < locked_until_dt:
                        remaining_min = int((locked_until_dt - datetime.now()).total_seconds() / 60) + 1
                        log_security_event(
                            "LOGIN_BLOCKED_LOCKED_ACCOUNT",
                            username=username,
                            user_id=user_dict["id"],
                            ip_address=ip_address,
                            details=f"Locked until {locked_until_str}"
                        )
                        raise PermissionError(
                            f"Account is temporarily locked due to repeated failed logins. "
                            f"Try again in {remaining_min} minute(s)."
                        )
                    else:
                        # Lockout expired, clear it
                        conn.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?", (user_dict["id"],))
                        conn.commit()
                        user_dict["failed_attempts"] = 0
                except ValueError:
                    pass

            user = user_dict
            # 3. Verify password hash using constant-time comparison
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), user['salt'], 100000)
            if not secrets.compare_digest(pwd_hash, user['password_hash']):
                # Increment failed attempts
                new_attempts = user_dict["failed_attempts"] + 1
                locked_until_val = None
                if new_attempts >= self.MAX_FAILED_ATTEMPTS:
                    locked_until_val = (datetime.now() + timedelta(minutes=self.LOCKOUT_MINUTES)).isoformat()
                    conn.execute(
                        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                        (new_attempts, locked_until_val, user_dict["id"])
                    )
                    conn.commit()
                    log_security_event(
                        "ACCOUNT_LOCKED",
                        username=username,
                        user_id=user_dict["id"],
                        ip_address=ip_address,
                        details=f"Locked for {self.LOCKOUT_MINUTES} min after {new_attempts} failed attempts"
                    )
                    raise PermissionError(
                        f"Account locked: 5 consecutive failed login attempts reached. "
                        f"Locked for {self.LOCKOUT_MINUTES} minutes."
                    )
                else:
                    conn.execute(
                        "UPDATE users SET failed_attempts = ? WHERE id = ?",
                        (new_attempts, user_dict["id"])
                    )
                    conn.commit()
                    log_security_event(
                        "LOGIN_FAILED_PASSWORD_MISMATCH",
                        username=username,
                        user_id=user_dict["id"],
                        ip_address=ip_address,
                        details=f"Failed attempt {new_attempts}/{self.MAX_FAILED_ATTEMPTS}"
                    )
                return None

            # 4. Successful credentials verification: reset failed counters
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_dict["id"],)
            )
            conn.commit()

            # Check MFA lockout if MFA is enabled
            if user_dict.get("mfa_enabled") == 1:
                mfa_service.check_mfa_lockout(user_dict)

            # -------------------------------------------------------------
            # MFA Verification / Challenge Branch
            # -------------------------------------------------------------
            # Branch A: Caller supplied a TOTP code directly
            if totp_code is not None:
                if user_dict.get("mfa_enabled") == 1 and user_dict.get("mfa_secret"):
                    try:
                        secret = mfa_service.decrypt_totp_secret(user_dict["mfa_secret"], user_dict["id"])
                    except Exception as e:
                        log_security_event("MFA_DECRYPTION_ERROR", username=username, user_id=user_dict["id"], details=str(e))
                        raise PermissionError("Internal security error during MFA validation.")

                    is_valid, matched_step, err_msg = mfa_service.verify_totp_code(
                        secret, totp_code, user_dict.get("mfa_last_used_step", 0)
                    )
                    if not is_valid:
                        mfa_service.record_mfa_failed_attempt(user_dict["id"], ip_address)
                        log_security_event(
                            "LOGIN_FAILED_MFA_MISMATCH",
                            username=username,
                            user_id=user_dict["id"],
                            ip_address=ip_address,
                            details=err_msg or "Invalid code"
                        )
                        raise PermissionError(err_msg or "Invalid one-time verification code.")

                    # TOTP Verified: Update replay protection step and clear failed attempts
                    conn.execute(
                        "UPDATE users SET mfa_last_used_step = ?, mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = ?",
                        (matched_step, user_dict["id"])
                    )
                else:
                    raise PermissionError("MFA is not enrolled for this account.")

            # Branch B: Caller did NOT supply a TOTP code
            else:
                if user_dict.get("mfa_enabled") == 1:
                    # Enrolled user must pass MFA challenge; cannot issue session token
                    temp_token = mfa_service.create_pending_mfa_session(user_dict["id"], "LOGIN", ip_address=ip_address)
                    log_security_event("MFA_CHALLENGE_ISSUED", username=username, user_id=user_dict["id"], ip_address=ip_address)
                    return {
                        'status': 'MFA_REQUIRED',
                        'temp_token': temp_token,
                        'user_id': user_dict['id'],
                        'username': user_dict['username'],
                        'full_name': user_dict['full_name'],
                        'role': user_dict['role'],
                        'canonical_role': normalize_role(user_dict['role']),
                        'department': user_dict['department']
                    }
                elif mfa_challenge_mode:
                    # Unenrolled user logging in via UI must complete mandatory MFA enrollment.
                    # Reuse existing unexpired enrollment secret if one is already active (prevents QR churn on page reload).
                    active_enrollment = mfa_service.get_active_pending_enrollment(user_dict["id"])
                    if active_enrollment and active_enrollment.get("pending_secret"):
                        secret = active_enrollment["pending_secret"]
                        temp_token = active_enrollment["temp_token"]
                    else:
                        secret = mfa_service.generate_totp_secret()
                        temp_token = mfa_service.create_pending_mfa_session(
                            user_dict["id"], "ENROLLMENT", pending_secret=secret, ip_address=ip_address
                        )

                    uri = mfa_service.get_provisioning_uri(secret, user_dict['username'])
                    qr_png = mfa_service.generate_qr_code_png(uri)
                    log_security_event("MFA_ENROLLMENT_CHALLENGE_ISSUED", username=username, user_id=user_dict["id"], ip_address=ip_address)
                    return {
                        'status': 'MFA_ENROLLMENT_REQUIRED',
                        'temp_token': temp_token,
                        'user_id': user_dict['id'],
                        'username': user_dict['username'],
                        'full_name': user_dict['full_name'],
                        'role': user_dict['role'],
                        'canonical_role': normalize_role(user_dict['role']),
                        'department': user_dict['department'],
                        'secret': secret,
                        'uri': uri,
                        'qr_png': qr_png
                    }

            # 5 & 6. Session fixation prevention + idle-timeout session issuance
            token, expires_at_iso = _create_session_record(conn, user_dict["id"])
            conn.commit()

            log_security_event(
                "LOGIN_SUCCESS",
                username=username,
                user_id=user_dict["id"],
                role=user_dict["role"],
                ip_address=ip_address
            )

            return {
                'token': token,
                'user_id': user_dict['id'],
                'username': user_dict['username'],
                'full_name': user_dict['full_name'],
                'role': user_dict['role'],
                'canonical_role': normalize_role(user_dict['role']),
                'department': user_dict['department'],
                'is_active': user_dict['is_active'],
                'mfa_enabled': user_dict.get('mfa_enabled', 0),
                'expires_at': expires_at_iso
            }
        finally:
            conn.close()

    def verify_mfa(self, user_id: str, mfa_token: str) -> bool:
        """Verifies an MFA one-time token for user_id against stored secret."""
        if not user_id or not mfa_token:
            return False
        conn = database.get_connection()
        try:
            row = conn.execute(
                """
                SELECT mfa_enabled, mfa_secret, COALESCE(mfa_last_used_step, 0) as mfa_last_used_step,
                       COALESCE(mfa_failed_attempts, 0) as mfa_failed_attempts, mfa_locked_until
                FROM users WHERE id = ?
                """,
                (user_id,)
            ).fetchone()
            if not row or not row[0] or not row[1]:
                return False

            u_dict = dict(row)
            mfa_service.check_mfa_lockout(u_dict)

            secret = mfa_service.decrypt_totp_secret(row[1], user_id)
            is_valid, matched_step, _ = mfa_service.verify_totp_code(secret, mfa_token, row[2])
            if is_valid:
                conn.execute(
                    "UPDATE users SET mfa_last_used_step = ?, mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = ?",
                    (matched_step, user_id)
                )
                conn.commit()
                return True
            else:
                mfa_service.record_mfa_failed_attempt(user_id)
                return False
        except Exception:
            return False
        finally:
            conn.close()

    def get_user_claims(self, user_id: str) -> Optional[Dict[str, Any]]:
        conn = database.get_connection()
        try:
            row = conn.execute(
                "SELECT id, username, full_name, role, department, is_active FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


class EntraIDAuthAdapter(IdentityAdapter):
    """
    Microsoft Entra ID (Azure AD) SSO / MFA Adapter Interface.
    Prepared for enterprise OIDC / OAuth 2.0 PKCE authentication flow.
    Enforces enterprise MFA via Microsoft Conditional Access and OIDC role mapping.
    """
    DEFAULT_GROUP_ROLE_MAPPING = {
        "KT-Vault-Admins": "Administrator",
        "KT-Vault-Operations": "Operations",
        "KT-Vault-Visa": "Visa",
        "KT-Vault-Ticketing": "Ticketing",
        "KT-Vault-Sales": "Sales",
        "KT-Vault-Auditors": "Read-only Auditor"
    }

    def __init__(
        self,
        tenant_id: str = "",
        client_id: str = "",
        client_secret: Optional[str] = None,
        redirect_uri: str = "http://localhost:8501/oauth2/callback",
        group_role_mapping: Optional[Dict[str, str]] = None
    ):
        self.tenant_id = tenant_id.strip()
        self.client_id = client_id.strip()
        self.client_secret = client_secret.strip() if client_secret else None
        self.redirect_uri = redirect_uri.strip()
        self.group_role_mapping = group_role_mapping or self.DEFAULT_GROUP_ROLE_MAPPING.copy()

    @property
    def authority(self) -> str:
        tid = self.tenant_id or "common"
        return f"https://login.microsoftonline.com/{tid}"

    def is_configured(self) -> bool:
        return bool(self.tenant_id and self.client_id)

    def get_authorization_url(
        self,
        state: str,
        redirect_uri: Optional[str] = None,
        code_challenge: Optional[str] = None,
        nonce: Optional[str] = None
    ) -> str:
        """
        Builds the Microsoft Entra ID OIDC v2.0 authorization URL.
        """
        if not self.is_configured():
            raise RuntimeError("Entra ID is not configured with AZURE_TENANT_ID and AZURE_CLIENT_ID.")

        target_redirect = redirect_uri or self.redirect_uri
        params = [
            ("client_id", self.client_id),
            ("response_type", "code"),
            ("redirect_uri", target_redirect),
            ("response_mode", "query"),
            ("scope", "openid profile email User.Read"),
            ("state", state)
        ]
        if code_challenge:
            params.append(("code_challenge", code_challenge))
            params.append(("code_challenge_method", "S256"))
        if nonce:
            params.append(("nonce", nonce))

        import urllib.parse
        qs = urllib.parse.urlencode(params)
        return f"{self.authority}/oauth2/v2.0/authorize?{qs}"

    def get_logout_url(self, post_logout_redirect_uri: Optional[str] = None) -> str:
        """
        Returns the Microsoft single logout endpoint URL.
        """
        target = post_logout_redirect_uri or self.redirect_uri
        import urllib.parse
        return f"{self.authority}/oauth2/v2.0/logout?post_logout_redirect_uri={urllib.parse.quote(target)}"

    def map_claims_to_role(self, claims: Dict[str, Any]) -> str:
        """
        Maps Entra ID token claims (groups or roles) to canonical KT Vault roles.
        Fails closed: if no matching group exists, raises PermissionError.
        """
        assigned_groups = set()
        # Check standard Entra ID claim locations
        if "groups" in claims and isinstance(claims["groups"], list):
            assigned_groups.update(claims["groups"])
        if "roles" in claims and isinstance(claims["roles"], list):
            assigned_groups.update(claims["roles"])
        if "wids" in claims and isinstance(claims["wids"], list):
            assigned_groups.update(claims["wids"])

        # Role priority order: Administrator > Operations > Visa > Ticketing > Sales > Read-only Auditor
        priority = ["Administrator", "Operations", "Visa", "Ticketing", "Sales", "Read-only Auditor"]
        
        matched_roles = set()
        for g in assigned_groups:
            if g in self.group_role_mapping:
                matched_roles.add(self.group_role_mapping[g])

        for r in priority:
            if r in matched_roles:
                return r

        # Fail closed: reject unauthorized users
        log_security_event(
            "SSO_ROLE_MAPPING_FAILED",
            username=claims.get("preferred_username") or claims.get("email"),
            details=f"User has claims with groups {list(assigned_groups)}, but none match KT Vault roles"
        )
        raise PermissionError(
            "Access Denied: Your enterprise account does not belong to an authorized KT Vault security group."
        )

    def validate_id_token_claims(
        self,
        claims: Dict[str, Any],
        expected_nonce: Optional[str] = None,
        clock_skew_seconds: int = 60
    ) -> Dict[str, Any]:
        """
        Validates standard JWT claims from Microsoft Entra ID.
        """
        import time
        now = time.time()

        # 1. Expiration check
        exp = claims.get("exp")
        if not exp or now > (float(exp) + clock_skew_seconds):
            raise PermissionError("OIDC token has expired.")

        # 2. Not before / issued at check
        nbf = claims.get("nbf", claims.get("iat"))
        if nbf and now < (float(nbf) - clock_skew_seconds):
            raise PermissionError("OIDC token is not yet valid.")

        # 3. Audience check
        aud = claims.get("aud")
        if aud != self.client_id:
            raise PermissionError(f"OIDC token audience mismatch (expected '{self.client_id}', got '{aud}').")

        # 4. Issuer check
        iss = claims.get("iss", "")
        if self.tenant_id and self.tenant_id not in iss:
            raise PermissionError(f"OIDC token issuer '{iss}' does not match tenant '{self.tenant_id}'.")

        # 5. Nonce check
        if expected_nonce and claims.get("nonce") != expected_nonce:
            raise PermissionError("OIDC token nonce mismatch.")

        return claims

    def authenticate(self, username: str, password: str, **kwargs) -> Optional[Dict[str, Any]]:
        if not self.is_configured():
            raise NotImplementedError(
                "Microsoft Entra ID is not yet configured. "
                "Requires AZURE_TENANT_ID and AZURE_CLIENT_ID environment settings."
            )
        # Delegated to OIDC redirect flow in web interface
        raise NotImplementedError("Direct password authentication is disabled for Entra ID SSO.")

    def verify_mfa(self, user_id: str, mfa_token: str) -> bool:
        # Managed natively by Microsoft Authenticator / Conditional Access Policies
        return True

    def get_user_claims(self, user_id: str) -> Optional[Dict[str, Any]]:
        return None


# Default adapter instance
_LOCAL_ADAPTER = LocalAuthAdapter()


def get_identity_adapter() -> IdentityAdapter:
    """
    Returns the active identity provider adapter based on configuration.
    Defaults to LocalAuthAdapter. Can be configured for EntraIDAuthAdapter via environment variables.
    """
    provider_type = os.environ.get("KT_AUTH_PROVIDER", "local").strip().lower()
    if provider_type in ("entra_id", "azure_ad", "oidc"):
        tenant_id = os.environ.get("AZURE_TENANT_ID", "")
        client_id = os.environ.get("AZURE_CLIENT_ID", "")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET")
        redirect_uri = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:8501/oauth2/callback")
        return EntraIDAuthAdapter(tenant_id, client_id, client_secret, redirect_uri)
    return _LOCAL_ADAPTER


# =====================================================================
# Public Service API (Preserves Full Backward Compatibility)
# =====================================================================

def authenticate_user(
    username: str,
    password: str,
    ip_address: str = "127.0.0.1",
    totp_code: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Authenticates a user against the active authentication adapter.
    Enforces lockout, status checks, session fixation rotation, and optional TOTP verification.
    """
    if not username or not password:
        return None
    return _LOCAL_ADAPTER.authenticate(
        username.strip(),
        password,
        ip_address=ip_address,
        totp_code=totp_code
    )


def get_user_by_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves the user associated with a session token.
    Validates server-side idle timeout (30 min), max session age (12h), and user active status.
    Automatically revokes expired or deactivated sessions and slides idle deadline on activity.
    """
    if not token or not isinstance(token, str):
        return None

    ensure_auth_schema()
    clean_token = token.strip()
    conn = database.get_connection()
    try:
        try:
            query = '''
                SELECT u.id, u.username, u.full_name, u.role,
                       COALESCE(u.is_active, 1) as is_active,
                       COALESCE(u.department, 'General') as department,
                       COALESCE(u.mfa_enabled, 0) as mfa_enabled,
                       s.created_at,
                       s.expires_at
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
            '''
            session = conn.execute(query, (clean_token,)).fetchone()
        except sqlite3.OperationalError as e:
            if "no such column" in str(e):
                fallback_query = '''
                    SELECT u.id, u.username, u.full_name, u.role,
                           s.expires_at
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.token = ?
                '''
                session = conn.execute(fallback_query, (clean_token,)).fetchone()
            else:
                raise

        if not session:
            return None

        session_dict = dict(session)
        if 'is_active' not in session_dict or session_dict['is_active'] is None:
            session_dict['is_active'] = 1
        if 'department' not in session_dict or not session_dict['department']:
            session_dict['department'] = 'General'
        if 'mfa_enabled' not in session_dict or session_dict['mfa_enabled'] is None:
            session_dict['mfa_enabled'] = 0

        now_dt = datetime.now()
        idle_delta = timedelta(minutes=get_idle_timeout_minutes())
        max_delta = timedelta(hours=get_max_session_hours())

        try:
            expires_at = datetime.fromisoformat(session_dict['expires_at'])
            if expires_at < now_dt:
                conn.execute("DELETE FROM sessions WHERE token = ?", (clean_token,))
                conn.commit()
                log_security_event("SESSION_EXPIRED", user_id=session_dict['id'], username=session_dict['username'])
                return None

            created_str = session_dict.get('created_at')
            abs_cap = None
            if created_str:
                try:
                    created_dt = datetime.fromisoformat(str(created_str))
                    abs_cap = created_dt + max_delta
                    if abs_cap < now_dt:
                        conn.execute("DELETE FROM sessions WHERE token = ?", (clean_token,))
                        conn.commit()
                        log_security_event("SESSION_MAX_AGE_EXPIRED", user_id=session_dict['id'], username=session_dict['username'])
                        return None
                except (ValueError, TypeError):
                    pass
        except Exception:
            return None

        # Check user active status (staff offboarding immediate revocation)
        if session_dict['is_active'] == 0:
            conn.execute("DELETE FROM sessions WHERE token = ?", (clean_token,))
            conn.commit()
            log_security_event("SESSION_REVOKED_DEACTIVATED_USER", user_id=session_dict['id'], username=session_dict['username'])
            return None

        # Slide idle timeout deadline forward on active request (bounded by absolute session cap)
        if expires_at <= now_dt + idle_delta:
            new_exp = now_dt + idle_delta
            if abs_cap is not None and new_exp > abs_cap:
                new_exp = abs_cap
            if (new_exp - expires_at).total_seconds() >= 5:
                try:
                    conn.execute("UPDATE sessions SET expires_at = ? WHERE token = ?", (new_exp.isoformat(), clean_token))
                    conn.commit()
                    session_dict['expires_at'] = new_exp.isoformat()
                except Exception:
                    pass

        session_dict['canonical_role'] = normalize_role(session_dict['role'])
        return session_dict
    finally:
        conn.close()


def logout(token: str):
    """
    Terminates the session and logs the logout event.
    """
    if not token:
        return
    conn = database.get_connection()
    try:
        user = conn.execute(
            "SELECT u.username, u.id FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?",
            (token.strip(),)
        ).fetchone()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token.strip(),))
        conn.commit()
        if user:
            log_security_event("LOGOUT", username=user["username"], user_id=user["id"])
    finally:
        conn.close()


def require_role(token: str, allowed_roles: List[str]) -> Dict[str, Any]:
    """
    Validates that the session token belongs to an active user with one of the allowed roles.
    Preserves backward compatibility with legacy role strings ('Admin', 'Supervisor', 'Staff')
    while mapping to canonical Phase 16 roles:
    - If allowed_roles contains 'Staff' or 'Sales': Grants access to all 4 office departments (ALL_OFFICE_ROLES).
    - If allowed_roles contains 'Supervisor' or 'Operations': Grants access to all authorized reviewers (AUTHORIZED_REVIEWER_ROLES).
    - If allowed_roles contains 'Admin' or 'Administrator': Strictly requires Administrator/Admin.
    """
    user = get_user_by_token(token)
    if not user:
        raise PermissionError("Unauthenticated: Invalid or expired session.")

    canonical_user_role = normalize_role(user['role'])
    
    # Expand allowed_roles using office hierarchy
    expanded_allowed = set()
    for r in allowed_roles:
        expanded_allowed.add(r)
        expanded_allowed.add(normalize_role(r))
        if r in ("Staff", "Sales"):
            expanded_allowed.update(ALL_OFFICE_ROLES)
        elif r in ("Supervisor", "Operations"):
            expanded_allowed.update(AUTHORIZED_REVIEWER_ROLES)
        elif r in ("Admin", "Administrator"):
            expanded_allowed.update(ADMIN_ROLES)

    if user['role'] not in expanded_allowed and canonical_user_role not in expanded_allowed:
        log_security_event(
            "ROLE_UNAUTHORIZED_ACCESS",
            username=user.get("username"),
            user_id=user.get("id"),
            role=user.get("role"),
            details=f"Required one of {allowed_roles}"
        )
        raise PermissionError(f"Unauthorized: Requires one of {allowed_roles}.")

    return user


def set_user_active_status(user_id: str, is_active: bool, admin_token: str) -> bool:
    """
    Enables or disables a user account (e.g. for staff offboarding).
    Requires Administrator permission.
    Immediately purges any active sessions if disabled.
    """
    require_permission(admin_token, "admin:user_manage")

    conn = database.get_connection()
    try:
        active_val = 1 if is_active else 0
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (active_val, user_id))
        if not is_active:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()

        admin = get_user_by_token(admin_token)
        log_security_event(
            "USER_STATUS_CHANGED",
            username=admin.get("username") if admin else "Admin",
            details=f"User {user_id} active set to {is_active}"
        )
        return True
    finally:
        conn.close()


def create_user_account(
    username: str,
    password: str,
    full_name: str,
    role: str,
    department: str = "General",
    admin_token: Optional[str] = None
) -> str:
    """
    Creates a new employee account with salt and PBKDF2 hash.
    Requires Administrator permission if admin_token is supplied.
    """
    if admin_token:
        require_permission(admin_token, "admin:user_manage")

    if not username or not password or not full_name or not role:
        raise ValueError("All user fields are required.")

    clean_user = username.strip().lower()
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    user_id = f"KT-U-{secrets.token_hex(4).upper()}"

    conn = database.get_connection()
    try:
        conn.execute(
            """
            INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, department, auth_provider)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'local')
            """,
            (user_id, clean_user, pwd_hash, salt, full_name.strip(), role.strip(), department.strip())
        )
        conn.commit()
        log_security_event("USER_CREATED", username=clean_user, user_id=user_id, role=role)
        return user_id
    finally:
        conn.close()


# =====================================================================
# Phase 5A: Public Multi-Factor Authentication Service API
# =====================================================================

def initiate_login(username: str, password: str, ip_address: str = "127.0.0.1") -> Optional[Dict[str, Any]]:
    """
    Initiates the login flow with mandatory MFA challenge support.
    Returns:
      - None if credentials invalid
      - Dict with status='MFA_REQUIRED' and temp_token if MFA is enrolled
      - Dict with status='MFA_ENROLLMENT_REQUIRED', temp_token, secret, uri, qr_png if enrollment needed
    """
    if not username or not password:
        return None
    return _LOCAL_ADAPTER.authenticate(username.strip(), password, mfa_challenge_mode=True, ip_address=ip_address)


def complete_mfa_login(temp_token: str, totp_code: str, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Completes the second factor for an enrolled user using their ephemeral temp_token and TOTP code.
    Enforces replay protection and rate limiting. Issues full session token upon success.
    """
    if not temp_token or not totp_code:
        raise PermissionError("Session token and verification code are required.")

    pending = mfa_service.get_pending_mfa_session(temp_token)
    if not pending or pending.get("session_type") != "LOGIN":
        raise PermissionError("MFA verification session has expired or is invalid. Please sign in again.")

    user_id = pending["user_id"]
    conn = database.get_connection()
    try:
        user = conn.execute(
            """
            SELECT id, username, full_name, role, department, is_active,
                   COALESCE(mfa_enabled, 0) as mfa_enabled, mfa_secret,
                   COALESCE(mfa_last_used_step, 0) as mfa_last_used_step,
                   COALESCE(mfa_failed_attempts, 0) as mfa_failed_attempts,
                   mfa_locked_until
            FROM users WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user or user["is_active"] == 0:
            mfa_service.delete_pending_mfa_session(temp_token)
            raise PermissionError("User account is inactive or disabled.")

        u_dict = dict(user)
        mfa_service.check_mfa_lockout(u_dict)

        if not u_dict["mfa_secret"]:
            mfa_service.delete_pending_mfa_session(temp_token)
            raise PermissionError("MFA secret is unconfigured. Please contact your administrator.")

        secret = mfa_service.decrypt_totp_secret(u_dict["mfa_secret"], user_id)
        is_valid, matched_step, err_msg = mfa_service.verify_totp_code(
            secret, totp_code, u_dict["mfa_last_used_step"]
        )

        if not is_valid:
            mfa_service.increment_pending_session_attempts(temp_token)
            mfa_service.record_mfa_failed_attempt(user_id, ip_address)
            log_security_event(
                "MFA_VERIFICATION_FAILED",
                username=u_dict["username"],
                user_id=user_id,
                ip_address=ip_address,
                details=err_msg or "Invalid TOTP code"
            )
            raise PermissionError(err_msg or "Invalid one-time verification code.")

        # Successful verification: update replay step, clear attempts, purge pending session
        conn.execute(
            "UPDATE users SET mfa_last_used_step = ?, mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = ?",
            (matched_step, user_id)
        )
        token, expires_at_iso = _create_session_record(conn, user_id)
        conn.commit()

        mfa_service.delete_pending_mfa_session(temp_token)
        log_security_event(
            "LOGIN_SUCCESS_MFA",
            username=u_dict["username"],
            user_id=user_id,
            role=u_dict["role"],
            ip_address=ip_address
        )

        return {
            'token': token,
            'user_id': u_dict['id'],
            'username': u_dict['username'],
            'full_name': u_dict['full_name'],
            'role': u_dict['role'],
            'canonical_role': normalize_role(u_dict['role']),
            'department': u_dict['department'],
            'is_active': u_dict['is_active'],
            'mfa_enabled': 1,
            'expires_at': expires_at_iso
        }
    finally:
        conn.close()


def complete_mfa_enrollment(
    temp_token: str,
    totp_code: str,
    ip_address: str = "127.0.0.1"
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Completes first-time MFA enrollment for a user.
    Verifies code against pending secret, encrypts secret at rest with AES-256-GCM,
    generates 8 recovery codes, sets mfa_enabled=1, and issues full session token.
    Returns: (authenticated_user_dict, plaintext_recovery_codes)
    """
    if not temp_token or not totp_code:
        raise PermissionError("Session token and verification code are required.")

    pending = mfa_service.get_pending_mfa_session(temp_token)
    if not pending or pending.get("session_type") != "ENROLLMENT":
        raise PermissionError("MFA setup session has expired or is invalid. Please sign in with your password to start a fresh setup session.")

    user_id = pending["user_id"]
    pending_secret = pending.get("pending_secret")
    if not pending_secret:
        mfa_service.delete_pending_mfa_session(temp_token)
        raise PermissionError("Enrollment secret is missing. Please restart enrollment.")

    is_valid, matched_step, err_msg = mfa_service.verify_totp_code(pending_secret, totp_code, 0)
    if not is_valid:
        mfa_service.increment_pending_session_attempts(temp_token)
        raise PermissionError(
            err_msg or "The 6-digit code did not match. Please ensure you are reading the current code for 'Khanna Travels Vault' from your authenticator app before the 30-second timer expires. If you have an older entry in your app, click 'Start Fresh / Regenerate QR Code' to reset."
        )

    # Encrypt secret at rest with AES-256-GCM
    encrypted_secret = mfa_service.encrypt_totp_secret(pending_secret, user_id)
    recovery_codes, hashes_json = mfa_service.generate_recovery_codes()

    conn = database.get_connection()
    try:
        user = conn.execute(
            "SELECT id, username, full_name, role, department, is_active FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        if not user or user["is_active"] == 0:
            mfa_service.delete_pending_mfa_session(temp_token)
            raise PermissionError("User account is inactive or disabled.")

        u_dict = dict(user)

        now_iso = datetime.now().isoformat()
        conn.execute(
            """
            UPDATE users 
            SET mfa_enabled = 1,
                mfa_secret = ?,
                mfa_enrolled_at = ?,
                mfa_last_used_step = ?,
                mfa_recovery_hashes = ?,
                mfa_failed_attempts = 0,
                mfa_locked_until = NULL
            WHERE id = ?
            """,
            (encrypted_secret, now_iso, matched_step, hashes_json, user_id)
        )

        # Issue full idle-timeout-protected session token
        token, expires_at_iso = _create_session_record(conn, user_id)
        conn.commit()

        mfa_service.delete_pending_mfa_session(temp_token)
        log_security_event(
            "MFA_ENROLLMENT_SUCCESS",
            username=u_dict["username"],
            user_id=user_id,
            role=u_dict["role"],
            ip_address=ip_address
        )

        auth_user = {
            'token': token,
            'user_id': u_dict['id'],
            'username': u_dict['username'],
            'full_name': u_dict['full_name'],
            'role': u_dict['role'],
            'canonical_role': normalize_role(u_dict['role']),
            'department': u_dict['department'],
            'is_active': u_dict['is_active'],
            'mfa_enabled': 1,
            'expires_at': expires_at_iso
        }
        return auth_user, recovery_codes
    finally:
        conn.close()


def complete_mfa_recovery_login(
    temp_token: str,
    recovery_code: str,
    ip_address: str = "127.0.0.1"
) -> Dict[str, Any]:
    """
    Completes emergency authentication using a single-use recovery code.
    Consumes the recovery code immediately.
    """
    if not temp_token or not recovery_code:
        raise PermissionError("Session token and recovery code are required.")

    pending = mfa_service.get_pending_mfa_session(temp_token)
    if not pending:
        raise PermissionError("Recovery session has expired or is invalid. Please sign in again.")

    user_id = pending["user_id"]
    conn = database.get_connection()
    try:
        user = conn.execute(
            """
            SELECT id, username, full_name, role, department, is_active,
                   COALESCE(mfa_failed_attempts, 0) as mfa_failed_attempts, mfa_locked_until
            FROM users WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user or user["is_active"] == 0:
            mfa_service.delete_pending_mfa_session(temp_token)
            raise PermissionError("User account is inactive or disabled.")

        u_dict = dict(user)
        mfa_service.check_mfa_lockout(u_dict)

        success = mfa_service.verify_and_consume_recovery_code(user_id, recovery_code)
        if not success:
            mfa_service.increment_pending_session_attempts(temp_token)
            mfa_service.record_mfa_failed_attempt(user_id, ip_address)
            log_security_event(
                "MFA_RECOVERY_CODE_FAILED",
                username=u_dict["username"],
                user_id=user_id,
                ip_address=ip_address
            )
            raise PermissionError("Invalid or already consumed recovery code.")

        mfa_service.clear_mfa_failed_attempts(user_id)
        mfa_service.delete_pending_mfa_session(temp_token)

        token, expires_at_iso = _create_session_record(conn, user_id)
        conn.commit()

        log_security_event(
            "MFA_RECOVERY_CODE_USED",
            username=u_dict["username"],
            user_id=user_id,
            role=u_dict["role"],
            ip_address=ip_address
        )

        return {
            'token': token,
            'user_id': u_dict['id'],
            'username': u_dict['username'],
            'full_name': u_dict['full_name'],
            'role': u_dict['role'],
            'canonical_role': normalize_role(u_dict['role']),
            'department': u_dict['department'],
            'is_active': u_dict['is_active'],
            'mfa_enabled': 1,
            'expires_at': expires_at_iso
        }
    finally:
        conn.close()


def regenerate_mfa_enrollment(temp_token: str, ip_address: str = "127.0.0.1") -> Dict[str, Any]:
    """
    Explicit user action: Invalidates the current pending enrollment secret,
    generates a brand new TOTP secret and QR code, and establishes a fresh 15-minute
    enrollment session.
    """
    if not temp_token:
        raise PermissionError("Session token is required to regenerate MFA setup.")

    pending = mfa_service.get_pending_mfa_session(temp_token)
    if not pending or pending.get("session_type") != "ENROLLMENT":
        raise PermissionError("Your setup session has expired or is invalid. Please sign in with your password again to start fresh.")

    user_id = pending["user_id"]
    conn = database.get_connection()
    try:
        user = conn.execute("SELECT id, username, full_name, role, department, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["is_active"] == 0:
            mfa_service.delete_pending_mfa_session(temp_token)
            raise PermissionError("User account is inactive or disabled.")

        u_dict = dict(user)

        # 1. Invalidate previous pending session and secret completely
        mfa_service.delete_pending_mfa_session(temp_token)

        # 2. Generate new secret, URI, and QR code PNG
        new_secret = mfa_service.generate_totp_secret()
        new_uri = mfa_service.get_provisioning_uri(new_secret, u_dict["username"])
        new_qr_png = mfa_service.generate_qr_code_png(new_uri)

        # 3. Create fresh 15-minute pending enrollment session
        new_token = mfa_service.create_pending_mfa_session(
            user_id, "ENROLLMENT", pending_secret=new_secret, ip_address=ip_address
        )

        log_security_event(
            "MFA_ENROLLMENT_REGENERATED",
            username=u_dict["username"],
            user_id=user_id,
            role=u_dict["role"],
            ip_address=ip_address,
            details="User explicitly regenerated MFA enrollment QR code; previous secret invalidated."
        )

        return {
            'status': 'MFA_ENROLLMENT_REQUIRED',
            'temp_token': new_token,
            'user_id': u_dict['id'],
            'username': u_dict['username'],
            'full_name': u_dict['full_name'],
            'role': u_dict['role'],
            'canonical_role': normalize_role(u_dict['role']),
            'department': u_dict['department'],
            'secret': new_secret,
            'uri': new_uri,
            'qr_png': new_qr_png
        }
    finally:
        conn.close()


def admin_reset_user_mfa(admin_token: str, target_user_id: str, reason: str = "Administrator MFA reset") -> bool:
    """
    Administrator-controlled recovery: Resets a user's MFA enrollment,
    revoking all active and pending sessions for that user.
    Requires 'admin:user_manage' permission.
    """
    admin = require_permission(admin_token, "admin:user_manage")

    conn = database.get_connection()
    try:
        user = conn.execute("SELECT id, username FROM users WHERE id = ?", (target_user_id,)).fetchone()
        if not user:
            raise ValueError(f"Target user '{target_user_id}' does not exist.")

        # Purge active and pending sessions
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_user_id,))
        conn.execute("DELETE FROM pending_mfa_sessions WHERE user_id = ?", (target_user_id,))

        # Reset MFA fields
        conn.execute(
            """
            UPDATE users 
            SET mfa_enabled = 0,
                mfa_secret = NULL,
                mfa_enrolled_at = NULL,
                mfa_last_used_step = 0,
                mfa_failed_attempts = 0,
                mfa_locked_until = NULL,
                mfa_recovery_hashes = NULL
            WHERE id = ?
            """,
            (target_user_id,)
        )
        conn.commit()

        log_security_event(
            "MFA_ADMIN_RESET",
            username=admin.get("username", "Admin"),
            user_id=admin.get("id"),
            role=admin.get("role"),
            details=f"Reset MFA for user {user['username']} ({target_user_id}). Reason: {reason}"
        )
        return True
    finally:
        conn.close()


def get_user_mfa_status(user_id: str) -> Dict[str, Any]:
    """Returns public MFA status metadata for a user."""
    conn = database.get_connection()
    try:
        row = conn.execute(
            """
            SELECT mfa_enabled, mfa_enrolled_at, mfa_recovery_hashes, mfa_failed_attempts, mfa_locked_until
            FROM users WHERE id = ?
            """,
            (user_id,)
        ).fetchone()
        if not row:
            return {"mfa_enabled": False, "mfa_enrolled_at": None, "recovery_codes_remaining": 0}

        rec_codes = 0
        if row[2]:
            try:
                rec_codes = len(json.loads(row[2]))
            except Exception:
                pass

        return {
            "mfa_enabled": bool(row[0]),
            "mfa_enrolled_at": row[1],
            "recovery_codes_remaining": rec_codes,
            "failed_attempts": row[3] or 0,
            "locked_until": row[4]
        }
    finally:
        conn.close()

def rotate_user_recovery_codes(
    session_token: str,
    totp_code: str,
    ip_address: str = "127.0.0.1"
) -> List[str]:
    """
    Rotates all emergency recovery codes for the currently authenticated user.
    Requires fresh step-up TOTP verification from their authenticator app.
    Atomically invalidates all prior recovery codes and replaces them with 8 new codes.
    Strictly bound to session_token (no arbitrary target_user_id accepted).
    Returns the list of 8 new plaintext recovery codes.
    """
    if not session_token or not isinstance(session_token, str):
        raise PermissionError("Active session token is required to rotate recovery codes.")
    if not totp_code or not isinstance(totp_code, str):
        raise PermissionError("A valid 6-digit authenticator code is required.")

    user = get_user_by_token(session_token)
    if not user or user.get("is_active") == 0:
        raise PermissionError("Session has expired or is invalid. Please sign in again.")

    user_id = user["id"]
    conn = database.get_connection()
    try:
        row = conn.execute(
            """
            SELECT id, username, full_name, role, department, is_active,
                   mfa_enabled, mfa_secret, mfa_last_used_step,
                   COALESCE(mfa_failed_attempts, 0) as mfa_failed_attempts, mfa_locked_until
            FROM users WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not row or row["is_active"] == 0:
            raise PermissionError("User account is inactive or disabled.")

        u_dict = dict(row)
        if not u_dict.get("mfa_enabled") or not u_dict.get("mfa_secret"):
            raise PermissionError("MFA is not enabled for this account.")

        mfa_service.check_mfa_lockout(u_dict)

        try:
            secret = mfa_service.decrypt_totp_secret(u_dict["mfa_secret"], user_id)
        except Exception as e:
            raise RuntimeError(f"Unable to decrypt MFA secret for verification: {e}")

        is_valid, matched_step, err_msg = mfa_service.verify_totp_code(
            secret, totp_code, u_dict.get("mfa_last_used_step") or 0
        )

        if not is_valid:
            mfa_service.record_mfa_failed_attempt(user_id, ip_address)
            log_security_event(
                "MFA_RECOVERY_CODES_ROTATION_FAILED",
                username=u_dict["username"],
                user_id=user_id,
                role=u_dict["role"],
                ip_address=ip_address,
                details=f"Failed step-up TOTP verification for recovery code rotation: {err_msg}"
            )
            raise PermissionError(err_msg or "Invalid one-time passcode.")

        # Successfully verified: clear failed attempts
        mfa_service.clear_mfa_failed_attempts(user_id)

        # Generate 8 brand new recovery codes
        new_plaintext_codes, new_hashes_json = mfa_service.generate_recovery_codes(8)

        # Atomically replace hashes and update last used step
        conn.execute(
            """
            UPDATE users
            SET mfa_recovery_hashes = ?,
                mfa_last_used_step = ?
            WHERE id = ?
            """,
            (new_hashes_json, matched_step, user_id)
        )
        conn.commit()

        log_security_event(
            "MFA_RECOVERY_CODES_ROTATED",
            username=u_dict["username"],
            user_id=user_id,
            role=u_dict["role"],
            ip_address=ip_address,
            details="User successfully rotated all emergency recovery codes via step-up TOTP verification."
        )

        return new_plaintext_codes
    finally:
        conn.close()
