"""
KT Vault V3 - Encryption Key Management and Recovery Service (key_management.py)
Phase 15B-3B.2: Secure Key Storage, Versioned Identification & Disaster Recovery Escrow

Architecture:
1. Windows DPAPI Key Provider (WindowsDPAPIKeyProvider):
   - At-rest key protection using Windows Cryptographic Data Protection API (DPAPI).
   - Local master keys are encrypted with user/machine cryptographic credentials via CryptProtectData.
   - Encrypted blobs (*.dpapi) are saved in a restricted keys directory.
   - Decryption occurs entirely in volatile memory via CryptUnprotectData.
   - Never logs or exposes raw key material; __repr__ and string conversions are redacted.
2. Cross-Platform Key Escrow & Disaster Recovery (KeyEscrowService):
   - Portable recovery package format: KT_VAULT_KEY_ESCROW_V1.
   - Key derivation: PBKDF2-HMAC-SHA256 with 600,000 iterations and 16-byte cryptographically random salt.
   - Authenticated encryption: AES-256-GCM with unique 12-byte nonce and 16-byte authentication tag.
   - Additional Authenticated Data (AAD) strictly binds escrow payload to its key_id.
   - Completely cross-platform (Windows / Linux / macOS) for disaster recovery and system migration.
3. Secrecy Preservation:
   - Zero plaintext keys in logs, audit records, or console output.
   - Safe key fingerprints (truncated SHA-256 hashes) used for administrator verification.
"""

import os
import sys
import json
import hashlib
import secrets
import ctypes
from ctypes import wintypes
from datetime import datetime
from typing import Optional, Tuple, Dict, Any, List

# Ensure storage_service is importable
app_root = os.path.dirname(os.path.abspath(__file__))
if app_root not in sys.path:
    sys.path.insert(0, app_root)

import storage_service
from storage_service import KeyProvider, AES256GCMCipher

ESCROW_FORMAT_VERSION = "KT_VAULT_KEY_ESCROW_V1"
DEFAULT_PBKDF2_ITERATIONS = 600000
MIN_PASSPHRASE_LENGTH = 12


# =====================================================================
# Windows Data Protection API (DPAPI) Implementation
# =====================================================================

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char))
    ]


def is_dpapi_supported() -> bool:
    """Returns True if Windows DPAPI is available in this runtime environment."""
    return sys.platform == "win32" and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "crypt32")


def dpapi_protect(plaintext: bytes, description: str = "KT Vault Key") -> bytes:
    """
    Encrypts plaintext bytes using Windows DPAPI (CryptProtectData).
    Tied to the current Windows user security context.
    """
    if not is_dpapi_supported():
        raise NotImplementedError("Windows DPAPI is only supported on Windows operating systems.")
        
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes.")
        
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    raw_in = ctypes.create_string_buffer(bytes(plaintext))
    blob_in = _DATA_BLOB(len(plaintext), ctypes.cast(raw_in, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()

    # CRYPTPROTECT_UI_FORBIDDEN = 0x01
    res = crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        ctypes.c_wchar_p(description),
        None,
        None,
        None,
        0x01,
        ctypes.byref(blob_out)
    )
    if not res:
        err = kernel32.GetLastError()
        raise RuntimeError(f"CryptProtectData failed with Windows error code: {err}")
        
    try:
        protected = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return protected
    finally:
        kernel32.LocalFree(blob_out.pbData)


def dpapi_unprotect(ciphertext: bytes) -> bytes:
    """
    Decrypts ciphertext bytes previously protected by Windows DPAPI (CryptUnprotectData).
    Requires execution under the same Windows user credentials on the same machine.
    """
    if not is_dpapi_supported():
        raise NotImplementedError("Windows DPAPI is only supported on Windows operating systems.")
        
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes.")
        
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    raw_in = ctypes.create_string_buffer(bytes(ciphertext))
    blob_in = _DATA_BLOB(len(ciphertext), ctypes.cast(raw_in, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()

    # CRYPTPROTECT_UI_FORBIDDEN = 0x01
    res = crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0x01,
        ctypes.byref(blob_out)
    )
    if not res:
        err = kernel32.GetLastError()
        raise RuntimeError(
            f"CryptUnprotectData failed with Windows error code: {err}. "
            "DPAPI blob cannot be decrypted (possibly running on a different machine or under a different Windows user)."
        )
        
    try:
        unprotected = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return unprotected
    finally:
        kernel32.LocalFree(blob_out.pbData)


# =====================================================================
# Windows DPAPI Key Provider
# =====================================================================

class WindowsDPAPIKeyProvider(KeyProvider):
    """
    Key provider utilizing Windows DPAPI to persist and retrieve 256-bit AES master keys.
    Each key is saved in a restricted .dpapi file in keys_dir.
    Never exposes raw key bytes in strings or logs.
    """

    def __init__(self, keys_dir: Optional[str] = None):
        if not is_dpapi_supported():
            raise NotImplementedError("Windows DPAPI is only supported on Windows operating systems.")
        if keys_dir:
            self.keys_dir = os.path.realpath(keys_dir)
        else:
            base_storage = storage_service.get_storage_root()
            self.keys_dir = os.path.realpath(os.path.join(base_storage, ".keys"))
        os.makedirs(self.keys_dir, exist_ok=True)

    def _get_key_path(self, key_id: str) -> str:
        clean_id = str(key_id).strip()
        if not clean_id or any(c in clean_id for c in r'\/<>:"|?*') or ".." in clean_id:
            raise ValueError(f"Invalid key_id format: '{key_id}'.")
        return os.path.join(self.keys_dir, f"{clean_id}.dpapi")

    def has_key(self, key_id: str = "master") -> bool:
        try:
            path = self._get_key_path(key_id)
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                return True
            if key_id == "master":
                prod_path = self._get_key_path("ktv_2026_v1")
                return os.path.isfile(prod_path) and os.path.getsize(prod_path) > 0
            return False
        except Exception:
            return False

    def get_key(self, key_id: str = "master") -> bytes:
        path = self._get_key_path(key_id)
        if not os.path.isfile(path):
            if key_id == "master":
                prod_path = self._get_key_path("ktv_2026_v1")
                if os.path.isfile(prod_path):
                    path = prod_path
            if not os.path.isfile(path):
                raise RuntimeError(f"Encryption key '{key_id}' is not available in DPAPI key store.")
            
        with open(path, "rb") as f:
            encrypted_blob = f.read()
            
        try:
            raw_key = dpapi_unprotect(encrypted_blob)
        except Exception as e:
            raise RuntimeError(f"Failed to unprotect key '{key_id}' via Windows DPAPI: {str(e)}")
            
        if len(raw_key) != 32:
            raise ValueError(f"Recovered key '{key_id}' has invalid length {len(raw_key)} bytes (expected 32).")
            
        return raw_key

    def save_key(self, key_id: str, key_bytes: bytes) -> str:
        """
        Encrypts key_bytes with Windows DPAPI and atomically writes to keys_dir.
        """
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise TypeError("key_bytes must be bytes.")
        if len(key_bytes) != 32:
            raise ValueError("key_bytes must be exactly 32 bytes (256 bits).")
            
        target_path = self._get_key_path(key_id)
        protected_blob = dpapi_protect(bytes(key_bytes), description=f"KT Vault Key: {key_id}")
        
        # Atomic write
        temp_path = f"{target_path}.{secrets.token_hex(4)}.tmp"
        try:
            with open(temp_path, "wb") as f:
                f.write(protected_blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, target_path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise e
            
        return target_path

    def list_keys(self) -> List[str]:
        """Lists all key IDs currently stored in the DPAPI keys directory."""
        if not os.path.exists(self.keys_dir):
            return []
        keys = []
        for f in os.listdir(self.keys_dir):
            if f.endswith(".dpapi"):
                keys.append(f[:-6])
        return sorted(keys)

    def __repr__(self) -> str:
        # Strictly redacted: never show raw key material
        return f"<WindowsDPAPIKeyProvider keys={self.list_keys()} dir='{self.keys_dir}'>"


# =====================================================================
# Cross-Platform Key Escrow & Disaster Recovery Service
# =====================================================================

class KeyEscrowService:
    """
    Cross-platform service for exporting and recovering master keys using
    high-iteration PBKDF2-HMAC-SHA256 and AES-256-GCM.
    
    Provides disaster recovery when the original computer fails or when
    migrating between Windows and Linux environments.
    """

    @staticmethod
    def compute_fingerprint(key_bytes: bytes) -> str:
        """
        Returns a safe 16-character hexadecimal fingerprint of the key.
        Never reveals raw key material.
        """
        if not isinstance(key_bytes, (bytes, bytearray)):
            raise TypeError("key_bytes must be bytes.")
        h = hashlib.sha256(b"KT_KEY_FINGERPRINT_V1:" + bytes(key_bytes)).hexdigest()
        return h[:16]

    @classmethod
    def create_escrow_package(
        cls,
        key: bytes,
        key_id: str,
        passphrase: str,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS
    ) -> Dict[str, Any]:
        """
        Exports a 256-bit symmetric key into a password-protected escrow dictionary.
        Uses PBKDF2-HMAC-SHA256 (600,000 iterations default) and AES-256-GCM.
        """
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits).")
        if not key_id or not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string.")
        if not passphrase or not isinstance(passphrase, str) or len(passphrase.strip()) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(f"Recovery passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters.")
        if iterations < 100000:
            raise ValueError("Iterations must be at least 100,000.")

        clean_key_id = key_id.strip()
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)

        # Derive 256-bit Key Encryption Key (KEK)
        kek = hashlib.pbkdf2_hmac("sha256", passphrase.strip().encode("utf-8"), salt, iterations)

        # Additional Authenticated Data binding payload to format and key_id
        aad = f"KT_ESCROW_V1|key_id:{clean_key_id}".encode("utf-8")

        cipher = AES256GCMCipher(kek)
        ciphertext, tag = cipher.encrypt(nonce, bytes(key), aad)

        fingerprint = cls.compute_fingerprint(key)

        return {
            "format": ESCROW_FORMAT_VERSION,
            "key_id": clean_key_id,
            "created_at": datetime.now().isoformat(),
            "kdf": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": iterations,
                "salt_hex": salt.hex()
            },
            "encryption": {
                "algorithm": "AES-256-GCM",
                "nonce_hex": nonce.hex(),
                "tag_hex": tag.hex(),
                "ciphertext_hex": ciphertext.hex()
            },
            "metadata": {
                "description": "KT Vault V3 Master Key Escrow Package",
                "key_fingerprint": fingerprint
            }
        }

    @classmethod
    def recover_key_from_escrow_package(
        cls,
        escrow_dict: Dict[str, Any],
        passphrase: str
    ) -> Tuple[str, bytes]:
        """
        Decrypts an escrow package and recovers the original 256-bit master key.
        Fails closed on incorrect passphrase or tampered package.
        Returns (key_id, raw_key).
        """
        if not isinstance(escrow_dict, dict):
            raise TypeError("escrow_dict must be a dictionary.")
        if escrow_dict.get("format") != ESCROW_FORMAT_VERSION:
            raise ValueError(f"Unsupported escrow format: '{escrow_dict.get('format')}'. Expected '{ESCROW_FORMAT_VERSION}'.")

        key_id = escrow_dict.get("key_id")
        if not key_id or not isinstance(key_id, str):
            raise ValueError("Invalid escrow package: missing key_id.")

        kdf_info = escrow_dict.get("kdf", {})
        if kdf_info.get("algorithm") != "PBKDF2-HMAC-SHA256":
            raise ValueError(f"Unsupported KDF algorithm: '{kdf_info.get('algorithm')}'.")

        iterations = kdf_info.get("iterations", DEFAULT_PBKDF2_ITERATIONS)
        salt_hex = kdf_info.get("salt_hex", "")
        try:
            salt = bytes.fromhex(salt_hex)
        except Exception:
            raise ValueError("Invalid salt_hex in escrow package.")

        enc_info = escrow_dict.get("encryption", {})
        if enc_info.get("algorithm") != "AES-256-GCM":
            raise ValueError(f"Unsupported encryption algorithm: '{enc_info.get('algorithm')}'.")

        try:
            nonce = bytes.fromhex(enc_info.get("nonce_hex", ""))
            tag = bytes.fromhex(enc_info.get("tag_hex", ""))
            ciphertext = bytes.fromhex(enc_info.get("ciphertext_hex", ""))
        except Exception:
            raise ValueError("Invalid hex encoding in escrow encryption fields.")

        # Derive KEK
        kek = hashlib.pbkdf2_hmac("sha256", passphrase.strip().encode("utf-8"), salt, iterations)
        aad = f"KT_ESCROW_V1|key_id:{key_id}".encode("utf-8")

        cipher = AES256GCMCipher(kek)
        try:
            recovered_key = cipher.decrypt(nonce, tag, ciphertext, aad)
        except Exception:
            raise ValueError("Key recovery failed: Incorrect recovery passphrase or corrupted escrow package.")

        if len(recovered_key) != 32:
            raise ValueError(f"Recovered key has invalid length: {len(recovered_key)} bytes.")

        # Verify fingerprint if present
        expected_fp = escrow_dict.get("metadata", {}).get("key_fingerprint")
        if expected_fp:
            actual_fp = cls.compute_fingerprint(recovered_key)
            if actual_fp != expected_fp:
                raise ValueError("Key recovery failed: Fingerprint mismatch on recovered key.")

        return key_id, recovered_key

    @classmethod
    def export_escrow_file(
        cls,
        key: bytes,
        key_id: str,
        passphrase: str,
        output_path: str,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS
    ) -> str:
        """Exports key escrow package to a JSON file atomically."""
        pkg = cls.create_escrow_package(key, key_id, passphrase, iterations)
        target_path = os.path.realpath(output_path)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        temp_path = f"{target_path}.{secrets.token_hex(4)}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(pkg, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, target_path)
        except Exception as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            raise e
        return target_path

    @classmethod
    def import_escrow_file(cls, escrow_path: str, passphrase: str) -> Tuple[str, bytes]:
        """Reads and decrypts an escrow JSON file, returning (key_id, raw_key)."""
        safe_path = os.path.realpath(escrow_path)
        if not os.path.isfile(safe_path):
            raise FileNotFoundError(f"Escrow file does not exist: '{safe_path}'.")

        with open(safe_path, "r", encoding="utf-8") as f:
            pkg = json.load(f)

        return cls.recover_key_from_escrow_package(pkg, passphrase)
