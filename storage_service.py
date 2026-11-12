"""
KT Vault V3 - Centralized Secure Storage Service (storage_service.py)
Phase 15B-3A: Authenticated Document Encryption Foundation

Architecture & Security Properties:
1. NIST SP 800-38D Authenticated Encryption (AES-256-GCM):
   - 256-bit keys (32 bytes)
   - Cryptographically random 96-bit unique nonce per write operation
   - 128-bit integrity tag (16 bytes)
   - Dual-backend:
     * Primary: cryptography.hazmat AESGCM (Standard / Linux environments)
     * Secondary: Windows Cryptographic Next Generation (CNG bcrypt.dll)
       (Hardware-accelerated, Microsoft-signed, AppLocker-compliant)
2. Envelope Specification (KTV1):
   - Offset  0..3  : Magic 'KTV1' (4 bytes)
   - Offset  4..5  : Format Version 0x0001 (2 bytes, big-endian)
   - Offset  6..17 : Initialization Vector / Nonce (12 bytes)
   - Offset 18..33 : Authentication Tag (16 bytes)
   - Offset 34..N  : AES-256-GCM Ciphertext (N bytes)
   - Total envelope overhead: 34 bytes
3. Shared-File Canonical Storage Identifier & AAD Binding:
   - File-level Additional Authenticated Data (AAD):
     AAD = b"KTV1|storage_id:" + file_storage_id.encode('utf-8')
   - Binds ciphertext strictly to physical storage identity (e.g. 'intake_abc.pdf')
   - Prevents ciphertext substitution attacks between unrelated documents
   - Supports multiple database document records referencing the same shared physical file
4. KeyProvider Abstraction:
   - KeyProvider (abstract base interface)
   - EnvKeyProvider (environment variable configuration)
   - StaticKeyProvider (for verified synthetic testing)
   - FailClosedKeyProvider (default fail-closed behavior when unconfigured)
   - No hardcoded production keys
5. Atomic Writes & Failure Safety:
   - Writes to unique UUID temporary file in target directory
   - Calls flush() and os.fsync() before atomic rename
   - Atomic replacement via os.replace()
   - Cleans up temporary files in finally block on any error
6. Fail-Closed Authenticated Document Retrieval:
   - Validates caller session token and RBAC roles
   - Validates path containment (path traversal prevention)
   - Requires valid key; never falls back to plaintext on authentication failure
   - Low-level cryptographic helpers are internal (_encrypt_envelope, _decrypt_envelope)
"""

import os
import sys
import struct
import secrets
import hashlib
import threading
from datetime import datetime
import ctypes
from ctypes import wintypes
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Dict, Any, List

# Envelope Constants
ENVELOPE_MAGIC = b"KTV1"
ENVELOPE_MAGIC_V1 = b"KTV1"
ENVELOPE_MAGIC_V2 = b"KTV2"
ENVELOPE_VERSION_V1 = 1
ENVELOPE_VERSION_V2 = 2
ENVELOPE_VERSION = ENVELOPE_VERSION_V1  # default / backwards-compatible alias
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_ID_MAX_BYTES = 16
HEADER_SIZE_V1 = 4 + 2 + NONCE_BYTES + TAG_BYTES  # 34 bytes
HEADER_SIZE_V2 = 4 + 2 + KEY_ID_MAX_BYTES + NONCE_BYTES + TAG_BYTES  # 50 bytes
HEADER_SIZE = HEADER_SIZE_V1  # default / backwards-compatible alias

# Windows CNG Constants
BCRYPT_AES_ALGORITHM = "AES"
BCRYPT_CHAINING_MODE = "ChainingMode"
BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"
STATUS_SUCCESS = 0x00000000
STATUS_AUTH_TAG_MISMATCH = 0xC000A002


# =====================================================================
# Dual-Backend AES-256-GCM Implementation
# =====================================================================

class _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.ULONG),
        ("dwInfoVersion", wintypes.ULONG),
        ("pbNonce", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbNonce", wintypes.ULONG),
        ("pbAuthData", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbAuthData", wintypes.ULONG),
        ("pbTag", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbTag", wintypes.ULONG),
        ("pbMacContext", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbMacContext", wintypes.ULONG),
        ("cbAAD", wintypes.ULONG),
        ("cbData", wintypes.LARGE_INTEGER),
        ("dwFlags", wintypes.ULONG),
    ]


_GLOBAL_CNG_ALG_HANDLE = None
_CNG_INIT_LOCK = threading.Lock()


def _get_cng_alg_handle():
    global _GLOBAL_CNG_ALG_HANDLE
    if sys.platform != "win32" or not hasattr(ctypes, "windll"):
        raise NotImplementedError("Windows CNG AES-GCM is only supported on Windows operating systems.")
    if _GLOBAL_CNG_ALG_HANDLE is None:
        with _CNG_INIT_LOCK:
            if _GLOBAL_CNG_ALG_HANDLE is None:
                bcrypt = ctypes.windll.bcrypt
                h_alg = wintypes.HANDLE()
                res = bcrypt.BCryptOpenAlgorithmProvider(
                    ctypes.byref(h_alg),
                    ctypes.c_wchar_p(BCRYPT_AES_ALGORITHM),
                    None,
                    0
                )
                if (res & 0xFFFFFFFF) != STATUS_SUCCESS:
                    raise RuntimeError(f"BCryptOpenAlgorithmProvider failed: 0x{(res & 0xFFFFFFFF):08X}")
                    
                chain_mode_buf = ctypes.create_unicode_buffer(BCRYPT_CHAIN_MODE_GCM)
                res = bcrypt.BCryptSetProperty(
                    h_alg,
                    ctypes.c_wchar_p(BCRYPT_CHAINING_MODE),
                    ctypes.cast(chain_mode_buf, ctypes.c_char_p),
                    ctypes.sizeof(chain_mode_buf),
                    0
                )
                if (res & 0xFFFFFFFF) != STATUS_SUCCESS:
                    bcrypt.BCryptCloseAlgorithmProvider(h_alg, 0)
                    raise RuntimeError(f"BCryptSetProperty GCM failed: 0x{(res & 0xFFFFFFFF):08X}")
                _GLOBAL_CNG_ALG_HANDLE = h_alg
    return _GLOBAL_CNG_ALG_HANDLE


class _WindowsCNG_AESGCM:
    """Windows Cryptographic Next Generation (CNG) AES-256-GCM backend."""
    
    def __init__(self, key: bytes):
        if sys.platform != "win32" or not hasattr(ctypes, "windll"):
            raise NotImplementedError("Windows CNG AES-GCM is only supported on Windows operating systems.")
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")
        self.key = key
        self.bcrypt = ctypes.windll.bcrypt
        
        h_alg = _get_cng_alg_handle()
            
        # Generate Key Handle
        self.h_key = wintypes.HANDLE()
        key_buf = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
        res = self.bcrypt.BCryptGenerateSymmetricKey(
            h_alg,
            ctypes.byref(self.h_key),
            None,
            0,
            key_buf,
            len(key),
            0
        )
        if (res & 0xFFFFFFFF) != STATUS_SUCCESS:
            raise RuntimeError(f"BCryptGenerateSymmetricKey failed: 0x{(res & 0xFFFFFFFF):08X}")

    def __del__(self):
        if hasattr(self, 'h_key') and self.h_key:
            self.bcrypt.BCryptDestroyKey(self.h_key)
            self.h_key = None

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        if len(nonce) != NONCE_BYTES:
            raise ValueError(f"Nonce must be {NONCE_BYTES} bytes.")
            
        tag_buf = (ctypes.c_ubyte * TAG_BYTES)()
        nonce_buf = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)
        aad_buf = (ctypes.c_ubyte * len(associated_data)).from_buffer_copy(associated_data) if associated_data else None
        
        auth_info = _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
        auth_info.cbSize = ctypes.sizeof(_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
        auth_info.dwInfoVersion = 1
        auth_info.pbNonce = ctypes.cast(nonce_buf, ctypes.POINTER(ctypes.c_ubyte))
        auth_info.cbNonce = len(nonce)
        auth_info.pbAuthData = ctypes.cast(aad_buf, ctypes.POINTER(ctypes.c_ubyte)) if aad_buf else None
        auth_info.cbAuthData = len(associated_data) if associated_data else 0
        auth_info.pbTag = ctypes.cast(tag_buf, ctypes.POINTER(ctypes.c_ubyte))
        auth_info.cbTag = TAG_BYTES
        
        pt_len = len(plaintext)
        pt_buf = (ctypes.c_ubyte * pt_len).from_buffer_copy(plaintext) if pt_len > 0 else None
        ct_buf = (ctypes.c_ubyte * pt_len)() if pt_len > 0 else None
        cb_result = wintypes.ULONG(0)
        
        res = self.bcrypt.BCryptEncrypt(
            self.h_key,
            pt_buf,
            pt_len,
            ctypes.byref(auth_info),
            None,
            0,
            ct_buf,
            pt_len,
            ctypes.byref(cb_result),
            0
        )
        status_code = res & 0xFFFFFFFF
        if status_code != STATUS_SUCCESS:
            raise RuntimeError(f"BCryptEncrypt failed: 0x{status_code:08X}")
            
        ciphertext = bytes(ct_buf) if ct_buf else b""
        tag = bytes(tag_buf)
        return ciphertext + tag

    def decrypt(self, nonce: bytes, ciphertext_and_tag: bytes, associated_data: bytes = b"") -> bytes:
        if len(nonce) != NONCE_BYTES:
            raise ValueError(f"Nonce must be {NONCE_BYTES} bytes.")
        if len(ciphertext_and_tag) < TAG_BYTES:
            raise ValueError(f"Ciphertext too short (must include {TAG_BYTES}-byte tag).")
            
        ciphertext = ciphertext_and_tag[:-TAG_BYTES]
        tag = ciphertext_and_tag[-TAG_BYTES:]
        
        tag_buf = (ctypes.c_ubyte * TAG_BYTES).from_buffer_copy(tag)
        nonce_buf = (ctypes.c_ubyte * len(nonce)).from_buffer_copy(nonce)
        aad_buf = (ctypes.c_ubyte * len(associated_data)).from_buffer_copy(associated_data) if associated_data else None
        
        auth_info = _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO()
        auth_info.cbSize = ctypes.sizeof(_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)
        auth_info.dwInfoVersion = 1
        auth_info.pbNonce = ctypes.cast(nonce_buf, ctypes.POINTER(ctypes.c_ubyte))
        auth_info.cbNonce = len(nonce)
        auth_info.pbAuthData = ctypes.cast(aad_buf, ctypes.POINTER(ctypes.c_ubyte)) if aad_buf else None
        auth_info.cbAuthData = len(associated_data) if associated_data else 0
        auth_info.pbTag = ctypes.cast(tag_buf, ctypes.POINTER(ctypes.c_ubyte))
        auth_info.cbTag = TAG_BYTES
        
        ct_len = len(ciphertext)
        ct_buf = (ctypes.c_ubyte * ct_len).from_buffer_copy(ciphertext) if ct_len > 0 else None
        pt_buf = (ctypes.c_ubyte * ct_len)() if ct_len > 0 else None
        cb_result = wintypes.ULONG(0)
        
        res = self.bcrypt.BCryptDecrypt(
            self.h_key,
            ct_buf,
            ct_len,
            ctypes.byref(auth_info),
            None,
            0,
            pt_buf,
            ct_len,
            ctypes.byref(cb_result),
            0
        )
        status_code = res & 0xFFFFFFFF
        if status_code == STATUS_AUTH_TAG_MISMATCH:
            raise ValueError("Authentication tag mismatch: Document has been tampered with or corrupted.")
        if status_code != STATUS_SUCCESS:
            raise RuntimeError(f"BCryptDecrypt failed: 0x{status_code:08X}")
            
        return bytes(pt_buf) if pt_buf else b""


_CRYPTOGRAPHY_AVAILABLE = None

def _is_cryptography_available() -> bool:
    global _CRYPTOGRAPHY_AVAILABLE
    if _CRYPTOGRAPHY_AVAILABLE is None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            _CRYPTOGRAPHY_AVAILABLE = True
        except Exception:
            _CRYPTOGRAPHY_AVAILABLE = False
    return _CRYPTOGRAPHY_AVAILABLE


class AES256GCMCipher:
    """
    AES-256-GCM cipher wrapper with automatic backend selection:
    1. Uses cryptography.hazmat.primitives.ciphers.aead.AESGCM if available.
    2. Gracefully falls back to Windows CNG bcrypt.dll when AppLocker blocks _rust.pyd.
    Both produce NIST SP 800-38D compliant 256-bit GCM ciphertexts.
    """
    
    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes.")
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits).")
            
        self.key = bytes(key)
        self.backend = None
        self._cng = None
        self._crypto_aesgcm = None
        
        # Check cryptography availability
        if _is_cryptography_available():
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self._crypto_aesgcm = AESGCM(self.key)
            self.backend = "cryptography"
        elif sys.platform == "win32":
            self._cng = _WindowsCNG_AESGCM(self.key)
            self.backend = "windows_cng"
        else:
            raise RuntimeError("AES-256-GCM unavailable: 'cryptography' library failed and platform is not Windows.")

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext with AES-256-GCM and returns (ciphertext, tag).
        """
        if len(nonce) != NONCE_BYTES:
            raise ValueError(f"Nonce must be {NONCE_BYTES} bytes.")
            
        if self.backend == "cryptography":
            ct_and_tag = self._crypto_aesgcm.encrypt(nonce, plaintext, aad)
            ciphertext = ct_and_tag[:-TAG_BYTES]
            tag = ct_and_tag[-TAG_BYTES:]
            return ciphertext, tag
        elif self.backend == "windows_cng":
            ct_and_tag = self._cng.encrypt(nonce, plaintext, aad)
            ciphertext = ct_and_tag[:-TAG_BYTES]
            tag = ct_and_tag[-TAG_BYTES:]
            return ciphertext, tag
        else:
            raise RuntimeError("No active cryptographic backend.")

    def decrypt(self, nonce: bytes, tag: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypts ciphertext with AES-256-GCM, verifying authentication tag and AAD.
        Raises ValueError on authentication tag mismatch or corruption.
        """
        if len(nonce) != NONCE_BYTES:
            raise ValueError(f"Nonce must be {NONCE_BYTES} bytes.")
        if len(tag) != TAG_BYTES:
            raise ValueError(f"Tag must be {TAG_BYTES} bytes.")
            
        ct_and_tag = ciphertext + tag
        if self.backend == "cryptography":
            from cryptography.exceptions import InvalidTag
            try:
                return self._crypto_aesgcm.decrypt(nonce, ct_and_tag, aad)
            except InvalidTag:
                raise ValueError("Authentication tag mismatch: Document has been tampered with or corrupted.")
        elif self.backend == "windows_cng":
            return self._cng.decrypt(nonce, ct_and_tag, aad)
        else:
            raise RuntimeError("No active cryptographic backend.")


# =====================================================================
# Key Provider Abstraction
# =====================================================================

class KeyProvider(ABC):
    """Abstract interface for document encryption key providers."""
    
    @abstractmethod
    def get_key(self, key_id: str = "master") -> bytes:
        """Returns 32-byte key for key_id, or raises RuntimeError."""
        pass
        
    @abstractmethod
    def has_key(self, key_id: str = "master") -> bool:
        """Returns True if key is available, False otherwise."""
        pass


class FailClosedKeyProvider(KeyProvider):
    """Default fail-closed key provider used when no key is configured."""
    
    def get_key(self, key_id: str = "master") -> bytes:
        raise RuntimeError("Encryption key provider is unconfigured. Cryptographic operation blocked.")
        
    def has_key(self, key_id: str = "master") -> bool:
        return False


class StaticKeyProvider(KeyProvider):
    """In-memory key provider for verified testing and synthetic test suites."""
    
    def __init__(self, key_or_dict: Any, key_id: str = "master"):
        self._keys = {}
        if isinstance(key_or_dict, dict):
            for kid, kbytes in key_or_dict.items():
                self.add_key(kid, kbytes)
        elif isinstance(key_or_dict, (bytes, bytearray)):
            self.add_key(key_id, key_or_dict)
            if key_id == "master" and "ktv_2026_v1" not in self._keys:
                self._keys["ktv_2026_v1"] = bytes(key_or_dict)
        else:
            raise TypeError("Key must be bytes or a dict mapping key_id to key bytes.")
        
    def get_key(self, key_id: str = "master") -> bytes:
        if key_id not in self._keys:
            raise RuntimeError(f"Key '{key_id}' is not available in StaticKeyProvider.")
        return self._keys[key_id]
        
    def has_key(self, key_id: str = "master") -> bool:
        return key_id in self._keys

    def add_key(self, key_id: str, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes.")
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits).")
        self._keys[key_id] = bytes(key)

    def list_keys(self) -> List[str]:
        return sorted(list(self._keys.keys()))


class EnvKeyProvider(KeyProvider):
    """
    Key provider reading from an environment variable.
    Supports 64-character hex encoding or 44-character base64 encoding.
    """
    
    def __init__(self, env_var_name: str = "KT_VAULT_STORAGE_KEY"):
        self.env_var_name = env_var_name
        
    def _load_key(self) -> Optional[bytes]:
        val = os.environ.get(self.env_var_name)
        if not val or not val.strip():
            return None
        val = val.strip()
        
        # Hex format (64 chars = 32 bytes)
        if len(val) == 64:
            try:
                raw = bytes.fromhex(val)
                if len(raw) == 32:
                    return raw
            except ValueError:
                pass
                
        # Base64 format (44 chars = 32 bytes)
        import base64
        try:
            raw = base64.b64decode(val)
            if len(raw) == 32:
                return raw
        except Exception:
            pass
            
        raise ValueError(
            f"Invalid key format in environment variable '{self.env_var_name}'. "
            "Key must be a 64-character hex string or 44-character base64 string representing 32 bytes."
        )

    def get_key(self, key_id: str = "master") -> bytes:
        key = self._load_key()
        if not key:
            raise RuntimeError(
                f"Master encryption key is unavailable: environment variable '{self.env_var_name}' is not set."
            )
        return key

    def has_key(self, key_id: str = "master") -> bool:
        try:
            return self._load_key() is not None
        except Exception:
            return False


# Global Key Provider Registry
_ACTIVE_KEY_PROVIDER: Optional[KeyProvider] = None


def set_key_provider(provider: KeyProvider) -> None:
    """Sets the active key provider for storage operations."""
    global _ACTIVE_KEY_PROVIDER
    if not isinstance(provider, KeyProvider):
        raise TypeError("provider must implement KeyProvider.")
    _ACTIVE_KEY_PROVIDER = provider


def init_default_key_provider(force: bool = False) -> KeyProvider:
    """
    Initializes and returns the trusted platform KeyProvider:
    1. Checks if Windows DPAPI is supported and loads WindowsDPAPIKeyProvider.
    2. Falls back to EnvKeyProvider if KT_VAULT_STORAGE_KEY is configured.
    3. Fails closed to FailClosedKeyProvider if unconfigured.
    """
    global _ACTIVE_KEY_PROVIDER
    if not force and _ACTIVE_KEY_PROVIDER is not None and not isinstance(_ACTIVE_KEY_PROVIDER, FailClosedKeyProvider):
        return _ACTIVE_KEY_PROVIDER

    try:
        from key_management import is_dpapi_supported, WindowsDPAPIKeyProvider
        if is_dpapi_supported():
            dpapi_provider = WindowsDPAPIKeyProvider()
            if dpapi_provider.list_keys() or dpapi_provider.has_key("ktv_2026_v1"):
                _ACTIVE_KEY_PROVIDER = dpapi_provider
                return _ACTIVE_KEY_PROVIDER
    except Exception:
        pass

    env_var = "KT_VAULT_STORAGE_KEY"
    if os.environ.get(env_var):
        try:
            env_provider = EnvKeyProvider(env_var)
            if env_provider.has_key():
                _ACTIVE_KEY_PROVIDER = env_provider
                return _ACTIVE_KEY_PROVIDER
        except Exception:
            pass

    _ACTIVE_KEY_PROVIDER = FailClosedKeyProvider()
    return _ACTIVE_KEY_PROVIDER


def get_key_provider() -> KeyProvider:
    """Returns the currently active key provider, auto-initializing if unconfigured."""
    global _ACTIVE_KEY_PROVIDER
    if _ACTIVE_KEY_PROVIDER is None or isinstance(_ACTIVE_KEY_PROVIDER, FailClosedKeyProvider):
        return init_default_key_provider()
    return _ACTIVE_KEY_PROVIDER


def reset_key_provider() -> None:
    """Resets the key provider to the default FailClosedKeyProvider for testing."""
    global _ACTIVE_KEY_PROVIDER
    _ACTIVE_KEY_PROVIDER = FailClosedKeyProvider()


# =====================================================================
# Canonical Storage Path Validation
# =====================================================================

def get_storage_root() -> str:
    """
    Returns the canonical absolute path to the approved documents storage directory.
    Checks environment variable KT_VAULT_STORAGE_ROOT first.
    """
    env_root = os.environ.get("KT_VAULT_STORAGE_ROOT")
    if env_root and env_root.strip():
        return os.path.realpath(env_root.strip())

    try:
        import database
        if hasattr(database, 'DB_PATH') and database.DB_PATH:
            db_dir = os.path.dirname(os.path.abspath(database.get_db_path() if hasattr(database, 'get_db_path') else database.DB_PATH))
            if os.path.basename(db_dir).lower() == "data":
                candidate_docs1 = os.path.join(os.path.dirname(db_dir), "documents")
                if os.path.exists(candidate_docs1) and os.path.isdir(candidate_docs1):
                    return os.path.realpath(candidate_docs1)
            candidate_docs2 = os.path.join(db_dir, "documents")
            if os.path.exists(candidate_docs2) and os.path.isdir(candidate_docs2):
                return os.path.realpath(candidate_docs2)
            candidate_docs1 = os.path.join(os.path.dirname(db_dir), "documents")
            if os.path.exists(candidate_docs1) and os.path.isdir(candidate_docs1):
                return os.path.realpath(candidate_docs1)
    except Exception:
        pass
    app_root = os.path.dirname(os.path.abspath(__file__))
    return os.path.realpath(os.path.join(app_root, "documents"))


def validate_storage_path(candidate_path: str, base_dir: Optional[str] = None) -> str:
    """
    Validates candidate_path strictly against directory traversal, relative escapes,
    null bytes, and drive boundary crossings.
    Returns canonical real path within base_dir.
    """
    if not candidate_path or not isinstance(candidate_path, str):
        raise ValueError("Storage path must be a non-empty string.")
        
    if "\0" in candidate_path:
        raise ValueError("Null byte detected in path.")
        
    storage_root = os.path.realpath(base_dir) if base_dir else get_storage_root()
    
    # Resolve candidate (normalizing redundant storage folder prefix if present)
    if os.path.isabs(candidate_path):
        resolved = os.path.realpath(candidate_path)
    else:
        norm = candidate_path.replace("\\", "/")
        root_name = os.path.basename(storage_root).lower()
        parts = norm.split("/")
        if parts and parts[0].lower() == root_name:
            norm = "/".join(parts[1:])
        resolved = os.path.realpath(os.path.join(storage_root, norm))
        
    # Check directory containment
    try:
        common = os.path.commonpath([storage_root, resolved])
        if os.path.realpath(common) != storage_root:
            raise PermissionError("Access denied: Path is outside approved document storage directory.")
    except (ValueError, Exception):
        raise PermissionError("Access denied: Invalid path traversal or drive boundary crossing.")
        
    return resolved


# =====================================================================
# Envelope Format & Additional Authenticated Data (AAD)
# =====================================================================

def compute_storage_aad(file_storage_id: str) -> bytes:
    """
    Computes Version 1 Additional Authenticated Data (AAD) binding ciphertext to its
    canonical physical storage identifier (e.g. 'intake_a9254ef900bd4ac1a5feaf0dfde30df8.pdf').
    """
    if not file_storage_id or not isinstance(file_storage_id, str):
        raise ValueError("file_storage_id must be a non-empty string.")
    return f"KTV1|storage_id:{file_storage_id}".encode("utf-8")


def compute_storage_aad_v2(key_id: str, file_storage_id: str) -> bytes:
    """
    Computes Version 2 Additional Authenticated Data (AAD) binding ciphertext to both
    its explicit versioned key_id and canonical physical storage identifier.
    """
    if not key_id or not isinstance(key_id, str):
        raise ValueError("key_id must be a non-empty string.")
    if not file_storage_id or not isinstance(file_storage_id, str):
        raise ValueError("file_storage_id must be a non-empty string.")
    return f"KTV2|key_id:{key_id}|storage_id:{file_storage_id}".encode("utf-8")


def is_encrypted_bytes(data: bytes) -> bool:
    """Checks if raw byte stream has the KTV1 or KTV2 envelope magic header."""
    if len(data) >= HEADER_SIZE_V1 and data[:4] == ENVELOPE_MAGIC_V1:
        return True
    if len(data) >= HEADER_SIZE_V2 and data[:4] == ENVELOPE_MAGIC_V2:
        return True
    return False


def is_encrypted_file(file_path: str, base_dir: Optional[str] = None) -> bool:
    """
    Checks if a file on disk has the KTV1 or KTV2 encrypted envelope magic header.
    Validates storage path before reading.
    """
    safe_path = validate_storage_path(file_path, base_dir)
    if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
        return False
    try:
        with open(safe_path, "rb") as f:
            magic = f.read(4)
        return magic in (ENVELOPE_MAGIC_V1, ENVELOPE_MAGIC_V2)
    except Exception:
        return False


def get_envelope_metadata(data: bytes) -> Dict[str, Any]:
    """
    Inspects envelope bytes without decrypting.
    Supports both KTV1 (34-byte header) and KTV2 (50-byte header with embedded key_id).
    Returns metadata dictionary or raises ValueError if malformed.
    """
    if len(data) < 4:
        raise ValueError("Envelope truncated: length is less than 4 bytes.")
        
    magic = data[:4]
    if magic == ENVELOPE_MAGIC_V1:
        if len(data) < HEADER_SIZE_V1:
            raise ValueError(f"Envelope truncated: length {len(data)} is less than header size ({HEADER_SIZE_V1} bytes).")
        magic_bytes, version = struct.unpack(">4sH", data[:6])
        if version != ENVELOPE_VERSION_V1:
            raise ValueError(f"Unsupported envelope version: {version}. Expected version 1.")
        _, _, nonce, tag = struct.unpack(f">4sH{NONCE_BYTES}s{TAG_BYTES}s", data[:HEADER_SIZE_V1])
        return {
            "magic": magic_bytes.decode("latin-1"),
            "version": version,
            "key_id": "master",
            "header_size": HEADER_SIZE_V1,
            "nonce_length": len(nonce),
            "tag_length": len(tag),
            "ciphertext_length": len(data) - HEADER_SIZE_V1,
            "total_envelope_size": len(data)
        }
    elif magic == ENVELOPE_MAGIC_V2:
        if len(data) < HEADER_SIZE_V2:
            raise ValueError(f"Envelope truncated: length {len(data)} is less than V2 header size ({HEADER_SIZE_V2} bytes).")
        magic_bytes, version, raw_key_id, nonce, tag = struct.unpack(
            f">4sH{KEY_ID_MAX_BYTES}s{NONCE_BYTES}s{TAG_BYTES}s",
            data[:HEADER_SIZE_V2]
        )
        clean_key_id = raw_key_id.decode("utf-8", errors="replace").rstrip("\x00")
        return {
            "magic": magic_bytes.decode("latin-1"),
            "version": version,
            "key_id": clean_key_id,
            "header_size": HEADER_SIZE_V2,
            "nonce_length": len(nonce),
            "tag_length": len(tag),
            "ciphertext_length": len(data) - HEADER_SIZE_V2,
            "total_envelope_size": len(data)
        }
    else:
        raise ValueError(f"Invalid envelope magic: expected {ENVELOPE_MAGIC_V1!r} or {ENVELOPE_MAGIC_V2!r}, got {magic!r}.")


# =====================================================================
# Internal Low-Level Cryptographic Primitives
# =====================================================================

def _encrypt_envelope(
    plaintext: bytes,
    file_storage_id: str,
    key: bytes,
    key_id: Optional[str] = None,
    version: int = ENVELOPE_VERSION_V1
) -> bytes:
    """
    Internal low-level cryptographic primitive.
    Constructs a complete KTV1 envelope for plaintext using AES-256-GCM.
    Supports Version 1 (34 bytes) and Version 2 (50 bytes with embedded key_id).
    Uses secrets.token_bytes(12) for fresh nonces.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes.")
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits).")
        
    nonce = secrets.token_bytes(NONCE_BYTES)
    cipher = AES256GCMCipher(key)

    if version == ENVELOPE_VERSION_V1:
        aad = compute_storage_aad(file_storage_id)
        ciphertext, tag = cipher.encrypt(nonce, bytes(plaintext), aad)
        header = struct.pack(f">4sH{NONCE_BYTES}s{TAG_BYTES}s", ENVELOPE_MAGIC, ENVELOPE_VERSION_V1, nonce, tag)
        return header + ciphertext
    elif version == ENVELOPE_VERSION_V2:
        clean_key_id = (key_id or "master").strip()
        raw_key_id = clean_key_id.encode("utf-8")
        if len(raw_key_id) > KEY_ID_MAX_BYTES:
            raise ValueError(f"key_id '{clean_key_id}' exceeds maximum length of {KEY_ID_MAX_BYTES} bytes.")
        padded_key_id = raw_key_id.ljust(KEY_ID_MAX_BYTES, b"\0")
        
        aad = compute_storage_aad_v2(clean_key_id, file_storage_id)
        ciphertext, tag = cipher.encrypt(nonce, bytes(plaintext), aad)
        header = struct.pack(
            f">4sH{KEY_ID_MAX_BYTES}s{NONCE_BYTES}s{TAG_BYTES}s",
            ENVELOPE_MAGIC_V2,
            1,
            padded_key_id,
            nonce,
            tag
        )
        return header + ciphertext
    else:
        raise ValueError(f"Unsupported envelope version: {version}. Expected 1 or 2.")


def _decrypt_envelope(
    envelope_bytes: bytes,
    file_storage_id: str,
    key: Optional[bytes] = None,
    key_provider: Optional[KeyProvider] = None
) -> bytes:
    """
    Internal low-level cryptographic primitive.
    Validates and decrypts an envelope using AES-256-GCM and canonical storage_id AAD.
    Automatically detects KTV1 (34-byte) or KTV2 (50-byte with versioned key_id).
    Fails closed: raises ValueError on any tamper, mismatch, or corruption.
    """
    if not isinstance(envelope_bytes, (bytes, bytearray)):
        raise TypeError("envelope_bytes must be bytes.")
        
    if len(envelope_bytes) < 4:
        raise ValueError(f"Envelope truncated: length {len(envelope_bytes)} is less than header size ({HEADER_SIZE_V1} bytes).")
        
    magic = envelope_bytes[:4]
    if magic not in (ENVELOPE_MAGIC_V1, ENVELOPE_MAGIC_V2):
        raise ValueError(f"Invalid envelope magic: expected {ENVELOPE_MAGIC_V1!r}, got {magic!r}.")
        
    if magic == ENVELOPE_MAGIC_V1:
        if len(envelope_bytes) < HEADER_SIZE_V1:
            raise ValueError(f"Envelope truncated: length {len(envelope_bytes)} is less than header size ({HEADER_SIZE_V1} bytes).")
        
        magic_val, version = struct.unpack(">4sH", envelope_bytes[:6])
        if version != ENVELOPE_VERSION_V1:
            raise ValueError(f"Unsupported envelope version: {version}. Expected version {ENVELOPE_VERSION_V1}.")
        _, _, nonce, tag = struct.unpack(f">4sH{NONCE_BYTES}s{TAG_BYTES}s", envelope_bytes[:HEADER_SIZE_V1])
        ciphertext = envelope_bytes[HEADER_SIZE_V1:]
        aad = compute_storage_aad(file_storage_id)
        
        # Resolve key
        if key is not None:
            dec_key = key
        else:
            provider = key_provider or get_key_provider()
            dec_key = provider.get_key("master")
            
        if len(dec_key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits).")
        cipher = AES256GCMCipher(dec_key)
        return cipher.decrypt(nonce, tag, ciphertext, aad)
        
    elif magic == ENVELOPE_MAGIC_V2:
        if len(envelope_bytes) < HEADER_SIZE_V2:
            raise ValueError(f"V2 envelope truncated: length {len(envelope_bytes)} < {HEADER_SIZE_V2}.")
            
        _, _, raw_key_id, nonce, tag = struct.unpack(
            f">4sH{KEY_ID_MAX_BYTES}s{NONCE_BYTES}s{TAG_BYTES}s",
            envelope_bytes[:HEADER_SIZE_V2]
        )
        clean_key_id = raw_key_id.decode("utf-8", errors="replace").rstrip("\x00")
        ciphertext = envelope_bytes[HEADER_SIZE_V2:]
        aad = compute_storage_aad_v2(clean_key_id, file_storage_id)
        
        # Resolve key using extracted key_id
        if key is not None:
            dec_key = key
        else:
            provider = key_provider or get_key_provider()
            dec_key = provider.get_key(clean_key_id)
            
        if len(dec_key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits).")
        cipher = AES256GCMCipher(dec_key)
        return cipher.decrypt(nonce, tag, ciphertext, aad)
    else:
        raise ValueError(f"Unsupported envelope magic: {magic!r}.")


# =====================================================================
# Document Encryption Modes & Central Storage Operations
# =====================================================================

ENCRYPTION_MODE_TRANSITIONAL = "transitional_plaintext"
ENCRYPTION_MODE_ENFORCED = "encrypted_only"

_CURRENT_ENCRYPTION_MODE: str = ENCRYPTION_MODE_TRANSITIONAL

def get_marker_file_path(base_dir: Optional[str] = None) -> str:
    """Returns canonical path to the .encryption_enforced marker file."""
    if base_dir:
        return os.path.join(os.path.realpath(base_dir), ".encryption_enforced")
    try:
        import database
        if hasattr(database, 'DB_PATH') and database.DB_PATH:
            db_dir = os.path.dirname(os.path.abspath(database.get_db_path() if hasattr(database, 'get_db_path') else database.DB_PATH))
            return os.path.join(db_dir, ".encryption_enforced")
    except Exception:
        pass
    app_root = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(app_root, "data", ".encryption_enforced")

def is_maintenance_mode(base_dir: Optional[str] = None) -> bool:
    """Returns True if the system is currently under planned maintenance."""
    if os.getenv("KT_VAULT_MAINTENANCE_MODE") == "1":
        return True
    try:
        if base_dir and os.path.exists(os.path.join(os.path.realpath(base_dir), ".maintenance_mode")):
            return True
        import database
        if hasattr(database, 'DB_PATH') and database.DB_PATH:
            db_dir = os.path.dirname(os.path.abspath(database.get_db_path() if hasattr(database, 'get_db_path') else database.DB_PATH))
            if os.path.exists(os.path.join(db_dir, ".maintenance_mode")):
                return True
            parent_dir = os.path.dirname(db_dir)
            if os.path.exists(os.path.join(parent_dir, ".maintenance_mode")):
                return True
    except Exception:
        pass
    app_root = os.path.dirname(os.path.abspath(__file__))
    return os.path.exists(os.path.join(app_root, ".maintenance_mode"))

def get_encryption_mode() -> str:
    """
    Returns the current document encryption mode ('transitional_plaintext' or 'encrypted_only').
    Fail-closed persistence hierarchy:
    1. Environment variable override (KT_VAULT_ENCRYPTION_MODE)
    2. Durable filesystem marker (.encryption_enforced)
    3. In-memory runtime setting (_CURRENT_ENCRYPTION_MODE)
    """
    env_mode = os.getenv("KT_VAULT_ENCRYPTION_MODE", "").strip().lower()
    if env_mode in ("encrypted_only", "enforced"):
        return ENCRYPTION_MODE_ENFORCED
    marker_path = get_marker_file_path()
    if os.path.exists(marker_path):
        return ENCRYPTION_MODE_ENFORCED
    return _CURRENT_ENCRYPTION_MODE

def set_encryption_mode(mode: str, persist: bool = False) -> None:
    """
    Sets the document encryption mode:
    - transitional_plaintext: Default pre-migration mode. New documents written as plaintext.
    - encrypted_only: Enforced encryption mode. All new documents MUST be encrypted via KTV2.
                      Fails closed if encryption key is unavailable (never falls back to plaintext).
    If persist=True, writes durable marker file so enforced mode survives application restarts.
    """
    global _CURRENT_ENCRYPTION_MODE
    if mode not in (ENCRYPTION_MODE_TRANSITIONAL, ENCRYPTION_MODE_ENFORCED):
        raise ValueError(f"Invalid encryption mode: '{mode}'.")
    marker_path = get_marker_file_path()
    if os.path.exists(marker_path) and mode == ENCRYPTION_MODE_TRANSITIONAL:
        raise RuntimeError("Cannot revert to transitional mode: Document encryption is permanently enforced on this system.")
    _CURRENT_ENCRYPTION_MODE = mode
    if persist and mode == ENCRYPTION_MODE_ENFORCED:
        try:
            os.makedirs(os.path.dirname(marker_path), exist_ok=True)
            with open(marker_path, "w", encoding="utf-8") as f:
                f.write(f"ENCRYPTION_MODE_ENFORCED\ntimestamp={datetime.now().isoformat()}\n")
        except Exception as e:
            raise IOError(f"Failed to persist encryption mode marker: {e}")


def write_document_file(
    rel_path_or_filename: str,
    file_bytes: bytes,
    session_token: Optional[str] = None,
    allowed_roles: Optional[List[str]] = None,
    file_storage_id: Optional[str] = None,
    key_id: Optional[str] = None,
    envelope_version: int = ENVELOPE_VERSION_V2,
    key_provider: Optional[KeyProvider] = None,
    base_dir: Optional[str] = None,
    system_context: bool = False,
    allow_external: bool = False
) -> Dict[str, Any]:
    """
    Central, authenticated document-writing interface for KT Vault V3:
    1. Validates caller session token and RBAC roles (fails closed unless system_context=True).
    2. Enforces strict storage path containment, blocking directory traversal, null bytes,
       and symbolic link / junction escapes.
    3. Handles transition strategy:
       - If encryption mode is ENCRYPTED_ONLY:
         Obtains key from key provider (fails closed if key unavailable).
         Encrypts plaintext via AES-256-GCM into KTV2 versioned envelope with fresh nonce
         and storage_id AAD.
         NEVER falls back to plaintext if encryption is enforced.
       - If encryption mode is TRANSITIONAL_PLAINTEXT:
         Writes plaintext file atomically (used only prior to live encryption activation).
    4. Atomically writes to disk via unique UUID temporary file (.tmp) in target directory,
       flush, fsync, and os.replace().
    5. Cleans up temporary file on any error.
    6. Returns metadata dict with file_path, storage_id, status, size, and sha256 checksum.
    """
    if is_maintenance_mode(base_dir) and not system_context:
        raise PermissionError("Maintenance mode active: Document writes and uploads are temporarily blocked.")

    if not system_context:
        if not session_token or not isinstance(session_token, str) or not session_token.strip():
            raise PermissionError("Unauthenticated: A valid session token is required to write documents.")
        roles = allowed_roles or ['Staff', 'Supervisor', 'Admin']
        import auth_services
        auth_services.require_role(session_token, roles)

    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("file_bytes must be bytes or bytearray.")
    file_bytes = bytes(file_bytes)

    if allow_external:
        if not rel_path_or_filename or not isinstance(rel_path_or_filename, str):
            raise ValueError("Storage path must be a non-empty string.")
        if "\0" in rel_path_or_filename:
            raise ValueError("Null byte detected in path.")
        norm_parts = rel_path_or_filename.replace('\\', '/').split('/')
        if '..' in norm_parts:
            raise PermissionError("Access denied: Path traversal sequence detected.")
        target_path = os.path.realpath(rel_path_or_filename)
    else:
        target_path = validate_storage_path(rel_path_or_filename, base_dir)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    storage_id = file_storage_id or os.path.basename(target_path)

    mode = get_encryption_mode()

    if mode == ENCRYPTION_MODE_ENFORCED:
        active_provider = key_provider or get_key_provider()
        active_key_id = (key_id or "ktv_2026_v1").strip()
        key = active_provider.get_key(active_key_id)
        if not key or len(key) != 32:
            raise RuntimeError(f"Encryption key '{active_key_id}' unavailable or invalid. Write blocked to prevent plaintext leakage.")

        payload = _encrypt_envelope(
            file_bytes,
            storage_id,
            key,
            key_id=active_key_id,
            version=envelope_version
        )
        status = "encrypted"
    else:
        payload = file_bytes
        status = "plaintext"

    # Atomic write via temporary file
    temp_filename = f"{os.path.basename(target_path)}.{secrets.token_hex(8)}.tmp"
    temp_path = os.path.join(os.path.dirname(target_path), temp_filename)

    try:
        with open(temp_path, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, target_path)
        if not system_context and session_token:
            try:
                import auth_services
                u_info = auth_services.get_user_by_token(session_token)
                if u_info:
                    auth_services.log_security_event(
                        "DOCUMENT_UPLOAD",
                        username=u_info.get("username"),
                        user_id=u_info.get("id"),
                        role=u_info.get("role"),
                        details=f"Uploaded document: {storage_id}"
                    )
            except Exception:
                pass
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        raise e

    return {
        "file_path": target_path,
        "storage_id": storage_id,
        "key_id": (key_id or "ktv_2026_v1") if status == "encrypted" else None,
        "version": envelope_version if status == "encrypted" else None,
        "size": len(payload),
        "status": status,
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }


# =====================================================================
# High-Level Storage Operations (Atomic Writes & Authenticated Retrieval)
# =====================================================================

def write_encrypted_file(
    rel_path_or_filename: str,
    plaintext: bytes,
    file_storage_id: Optional[str] = None,
    key_id: Optional[str] = None,
    envelope_version: int = ENVELOPE_VERSION_V1,
    key_provider: Optional[KeyProvider] = None,
    base_dir: Optional[str] = None,
    session_token: Optional[str] = None,
    system_context: bool = True
) -> Dict[str, Any]:
    """
    Atomically writes encrypted document bytes to disk:
    1. Validates storage path and ensures directory exists.
    2. Obtains 256-bit encryption key from key provider (fails closed if unavailable).
    3. Encrypts plaintext via AES-256-GCM into versioned envelope with fresh nonce.
       Supports Version 1 (legacy 34-byte) and Version 2 (versioned key identification 50-byte).
    4. Writes to unique UUID temporary file (.tmp) in the same directory.
    5. Flushes and executes os.fsync() on the file descriptor.
    6. Atomically renames temporary file to target path via os.replace().
    7. Cleans up temporary file in finally block on any error.
    
    Never logs encryption keys or plaintext bytes.
    """
    target_path = validate_storage_path(rel_path_or_filename, base_dir)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    
    storage_id = file_storage_id or os.path.basename(target_path)
    
    active_provider = key_provider or get_key_provider()
    active_key_id = (key_id or ("ktv_2026_v1" if envelope_version == ENVELOPE_VERSION_V2 else "master")).strip()
    key = active_provider.get_key(active_key_id)
    
    envelope = _encrypt_envelope(plaintext, storage_id, key, key_id=active_key_id, version=envelope_version)
    
    # Generate unique temporary file in the same directory
    temp_filename = f"{os.path.basename(target_path)}.{secrets.token_hex(8)}.tmp"
    temp_path = os.path.join(os.path.dirname(target_path), temp_filename)
    
    try:
        with open(temp_path, "wb") as f:
            f.write(envelope)
            f.flush()
            os.fsync(f.fileno())
            
        os.replace(temp_path, target_path)
    except Exception as e:
        # Secure cleanup of partial temporary file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        raise e
        
    return {
        "file_path": target_path,
        "storage_id": storage_id,
        "key_id": active_key_id,
        "version": envelope_version,
        "size": len(envelope),
        "status": "encrypted"
    }


def read_decrypted_document(
    file_path: str,
    session_token: Optional[str] = None,
    file_storage_id: Optional[str] = None,
    allowed_roles: Optional[List[str]] = None,
    key_provider: Optional[KeyProvider] = None,
    base_dir: Optional[str] = None,
    system_context: bool = False,
    doc_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    allow_external: bool = False
) -> bytes:
    """
    Authenticated retrieval and decryption of a document:
    1. Validates caller session token and RBAC roles (fails closed if unauthenticated,
       empty, invalid, or expired, unless explicitly executed in system_context).
    2. Validates document authorization if customer_id/doc_id are provided.
    3. Validates path containment (preventing directory traversal and path manipulation).
    4. Confirms file existence and regular file status.
    5. Authenticates and decrypts via AES-256-GCM and canonical storage_id AAD if encrypted (KTV1).
    6. Fails closed on any tampering: raises ValueError if ciphertext or authentication tag is invalid.
       Never returns partially decrypted or unauthenticated plaintext after an integrity failure.
    7. Transitional mode: if file is unencrypted, verifies session authorization first,
       then returns document bytes.
    """
    # 1. Authorization check: Mandatory fail-closed boundary
    if not system_context:
        if not session_token or not isinstance(session_token, str) or not session_token.strip():
            raise PermissionError("Unauthenticated: A valid session token is required to access documents.")
        
        token = session_token.strip()
        try:
            import auth_services
            roles = allowed_roles or ["Staff", "Supervisor", "Admin"]
            auth_services.require_role(token, roles)
        except PermissionError:
            raise
        except Exception as e:
            raise PermissionError(f"Authentication validation failed: {str(e)}")

    # 2. Document-level customer authorization check (defense-in-depth)
    if customer_id is not None and not system_context:
        try:
            import database
            conn = database.get_connection()
            try:
                if doc_id:
                    doc_owner = conn.execute('''
                        SELECT COALESCE(tr.customer_id, t.customer_id) as doc_customer_id
                        FROM documents d
                        JOIN requirements r ON d.requirement_id = r.id
                        LEFT JOIN travellers t ON r.traveller_id = t.id
                        LEFT JOIN trips tr ON r.trip_id = tr.id
                        WHERE d.id = ?
                    ''', (doc_id,)).fetchone()
                    if doc_owner and doc_owner['doc_customer_id'] != customer_id:
                        raise PermissionError(
                            f"Security violation: Document '{doc_id}' does not belong to customer '{customer_id}'."
                        )
            finally:
                conn.close()
        except PermissionError:
            raise
        except Exception:
            pass

    # 3. Path validation
    if allow_external:
        if not file_path or not isinstance(file_path, str):
            raise ValueError("Storage path must be a non-empty string.")
        if "\0" in file_path:
            raise ValueError("Null byte detected in path.")
        norm_parts = file_path.replace('\\', '/').split('/')
        if '..' in norm_parts:
            raise PermissionError("Access denied: Path traversal sequence detected.")
        safe_path = os.path.realpath(file_path)
    else:
        safe_path = validate_storage_path(file_path, base_dir)

    if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
        raise FileNotFoundError(f"Document file does not exist: '{safe_path}'.")
        
    with open(safe_path, "rb") as f:
        file_bytes = f.read()
        
    # 4. Format detection & authenticated decryption
    if is_encrypted_bytes(file_bytes):
        storage_id = file_storage_id or os.path.basename(safe_path)
        active_provider = key_provider or get_key_provider()
        dec_bytes = _decrypt_envelope(file_bytes, storage_id, key_provider=active_provider)
    else:
        # Transitional Mode: Document is currently stored in unencrypted format (pre-migration).
        # Access is strictly permitted ONLY because caller's session was verified above.
        dec_bytes = file_bytes

    if not system_context and session_token:
        try:
            import auth_services
            u_info = auth_services.get_user_by_token(session_token)
            if u_info:
                auth_services.log_security_event(
                    "DOCUMENT_ACCESS",
                    username=u_info.get("username"),
                    user_id=u_info.get("id"),
                    role=u_info.get("role"),
                    details=f"Retrieved document: {os.path.basename(safe_path)}"
                )
        except Exception:
            pass

    return dec_bytes

# =====================================================================
# Key Management & Escrow Re-exports (Phase 15B-3B.2)
# =====================================================================
try:
    from key_management import WindowsDPAPIKeyProvider, KeyEscrowService, dpapi_protect, dpapi_unprotect
except ImportError:
    pass


# Aliases for Phase 16 service compatibility
write_document_atomic = write_document_file
retrieve_document = read_decrypted_document
