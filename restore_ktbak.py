"""
KT Vault V3 - Portable Encrypted Backup Restoration Utility
Phase 15B-3B.4E Implementation

Restores and verifies authenticated, password-encrypted KT Vault backup (.ktbak) archives.
Completely standalone: zero runtime dependency on KT Vault codebase.

Supported Operating Systems & Cryptographic Backends:
  - Windows: Built-in Microsoft Cryptographic Next Generation (CNG System32\\bcrypt.dll).
    Requires no external packages, pip installs, or binary extensions.
  - Linux / macOS: Standard Python 'cryptography' library (pip install cryptography).

Security Controls:
  1. Cryptographic Authentication: AES-256-GCM authenticated decryption with PBKDF2-HMAC-SHA256.
  2. AAD Integrity Binding: Magic bytes, version, salt, and iteration count bound to auth tag.
  3. Path Traversal Defense: Blocks relative parent traversals (..), absolute paths, and drive escapes.
  4. Symlink/Hardlink Rejection: Strictly forbids symbolic and hard links within the archive.
  5. Archive Bomb Defense: Limits total file count, single-file size, and total uncompressed size.
  6. Overwrite Protection: Refuses to overwrite existing files unless explicitly authorized.
  7. Manifest Verification: Validates SHA-256 hashes of restored files against embedded manifest.
"""

import os
import sys
import io
import json
import struct
import hashlib
import tarfile
import getpass
import argparse
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

# Format Constants
MAGIC_BYTES = b"KTBK"
FORMAT_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
HEADER_SIZE = 4 + 2 + SALT_BYTES + 4 + NONCE_BYTES + TAG_BYTES  # 54 bytes
MIN_PBKDF2_ITERATIONS = 100_000

# Archive Extraction Security Limits
MAX_ARCHIVE_FILES = 10_000
MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024       # 50 MB
MAX_TOTAL_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB

# Windows CNG Constants
BCRYPT_AES_ALGORITHM = "AES"
BCRYPT_CHAINING_MODE = "ChainingMode"
BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"
STATUS_SUCCESS = 0x00000000
STATUS_AUTH_TAG_MISMATCH = 0xC000A002


class SecurityError(Exception):
    """Raised when an archive violates path safety, symlink rules, or resource limits."""
    pass


# =====================================================================
# Windows CNG AES-256-GCM Backend
# =====================================================================

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

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

    _CNG_ALG_HANDLE = None
    _CNG_LOCK = threading.Lock()

    def _get_cng_algorithm_handle():
        global _CNG_ALG_HANDLE
        if _CNG_ALG_HANDLE is None:
            with _CNG_LOCK:
                if _CNG_ALG_HANDLE is None:
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
                    _CNG_ALG_HANDLE = h_alg
        return _CNG_ALG_HANDLE

    class WindowsCNG_AES256GCM:
        """Windows Native CNG AES-256-GCM Authenticated Decryption Engine."""

        def __init__(self, key: bytes):
            if len(key) != 32:
                raise ValueError("AES-256 key must be exactly 32 bytes.")
            self.key = key
            self.bcrypt = ctypes.windll.bcrypt
            h_alg = _get_cng_algorithm_handle()
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
            if hasattr(self, "h_key") and self.h_key:
                try:
                    self.bcrypt.BCryptDestroyKey(self.h_key)
                except Exception:
                    pass
                self.h_key = None

        def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
            """Decrypts ciphertext with AES-256-GCM. Verifies auth tag and associated data."""
            if len(nonce) != NONCE_BYTES:
                raise ValueError(f"Nonce must be {NONCE_BYTES} bytes.")
            if len(tag) != TAG_BYTES:
                raise ValueError(f"Auth tag must be {TAG_BYTES} bytes.")

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
                raise ValueError("Authentication tag mismatch: Invalid passphrase or corrupted/tampered backup.")
            if status_code != STATUS_SUCCESS:
                raise RuntimeError(f"BCryptDecrypt failed: 0x{status_code:08X}")

            return bytes(pt_buf) if pt_buf else b""

else:
    WindowsCNG_AES256GCM = None


# =====================================================================
# Cross-Platform Fallback (Cryptography Hazmat)
# =====================================================================

class Cryptography_AES256GCM:
    """Cross-Platform AES-256-GCM backend using the standard cryptography library."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes.")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self.cipher = AESGCM(key)
        except ImportError as e:
            raise RuntimeError(
                "The 'cryptography' library is required on Linux/macOS. Install via: pip install cryptography"
            ) from e

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
        from cryptography.exceptions import InvalidTag
        ct_and_tag = ciphertext + tag
        try:
            return self.cipher.decrypt(nonce, ct_and_tag, associated_data)
        except InvalidTag:
            raise ValueError("Authentication tag mismatch: Invalid passphrase or corrupted/tampered backup.")


def get_cipher_engine(key: bytes, force_backend: Optional[str] = None):
    """Factory returning the appropriate AES-256-GCM cipher engine."""
    if force_backend == "cryptography":
        return Cryptography_AES256GCM(key)
    elif force_backend == "cng":
        if WindowsCNG_AES256GCM is None:
            raise RuntimeError("Windows CNG backend is only available on Windows platforms.")
        return WindowsCNG_AES256GCM(key)

    if sys.platform == "win32" and WindowsCNG_AES256GCM is not None:
        return WindowsCNG_AES256GCM(key)
    else:
        return Cryptography_AES256GCM(key)


# =====================================================================
# Envelope Parsing and Key Derivation
# =====================================================================

def parse_header(raw_data: bytes) -> Dict[str, Any]:
    """Parses and validates the KTBK envelope header."""
    if len(raw_data) < HEADER_SIZE:
        raise ValueError(f"File too small to be a valid KTBK archive ({len(raw_data)} < {HEADER_SIZE} bytes).")

    magic = raw_data[:4]
    if magic != MAGIC_BYTES:
        raise ValueError(f"Invalid file format: expected magic {MAGIC_BYTES}, got {magic}.")

    version = struct.unpack(">H", raw_data[4:6])[0]
    if version != FORMAT_VERSION:
        raise ValueError(f"Unsupported backup version: {version} (expected {FORMAT_VERSION}).")

    salt = raw_data[6:22]
    iterations = struct.unpack(">I", raw_data[22:26])[0]
    if iterations < MIN_PBKDF2_ITERATIONS:
        raise ValueError(f"Insecure iteration count in header: {iterations} (minimum is {MIN_PBKDF2_ITERATIONS}).")

    nonce = raw_data[26:38]
    tag = raw_data[38:54]
    ciphertext = raw_data[54:]

    return {
        "version": version,
        "salt": salt,
        "iterations": iterations,
        "nonce": nonce,
        "tag": tag,
        "ciphertext": ciphertext
    }


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """Derives a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=32)


def compute_aad(salt: bytes, iterations: int) -> bytes:
    """Recomputes authenticated additional data to verify header integrity."""
    return MAGIC_BYTES + struct.pack(">H", FORMAT_VERSION) + salt + struct.pack(">I", iterations)


# =====================================================================
# Hardened Archive Extraction
# =====================================================================

def safe_extract_tar(
    tar: tarfile.TarFile,
    dest_dir: str,
    overwrite: bool = False,
    verify_only: bool = False
) -> List[str]:
    """
    Safely inspects and extracts members from a tarfile object.
    Enforces path traversal protection, symlink prohibition, size limits, and overwrite controls.
    """
    dest_abs = os.path.abspath(dest_dir)
    extracted_rel_paths = []

    total_files = 0
    total_uncompressed_bytes = 0

    # Pass 1: Strict Validation of All Members
    for member in tar.getmembers():
        # 1. Symlink and Hardlink Rejection
        if member.issym() or member.islnk():
            raise SecurityError(
                f"Security Violation: Symbolic and hard links are strictly forbidden in backups ({member.name})."
            )

        # 2. Special Device / FIFO Rejection
        if not (member.isreg() or member.isdir()):
            raise SecurityError(
                f"Security Violation: Non-standard file type detected in archive ({member.name})."
            )

        # 3. Path Traversal & Escape Prevention
        raw_name = member.name.replace("\\", "/")
        if raw_name.startswith("/") or (len(raw_name) > 1 and raw_name[1] == ":"):
            raise SecurityError(f"Security Violation: Absolute path detected in archive member ({member.name}).")

        path_parts = Path(raw_name).parts
        if ".." in path_parts:
            raise SecurityError(f"Security Violation: Directory traversal (..) detected in member ({member.name}).")

        target_path = os.path.abspath(os.path.join(dest_abs, raw_name))
        try:
            common = os.path.commonpath([dest_abs, target_path])
            if common != dest_abs:
                raise SecurityError(f"Security Violation: Path traversal escape attempt ({member.name}).")
        except ValueError:
            raise SecurityError(f"Security Violation: Drive path escape attempt ({member.name}).")

        # 4. Archive Bomb and Resource Exhaustion Checks
        if member.isreg():
            total_files += 1
            if total_files > MAX_ARCHIVE_FILES:
                raise SecurityError(f"Archive bomb protection: Member count exceeds {MAX_ARCHIVE_FILES:,}.")

            if member.size > MAX_SINGLE_FILE_BYTES:
                raise SecurityError(
                    f"Archive bomb protection: File {member.name} exceeds {MAX_SINGLE_FILE_BYTES:,} bytes."
                )

            total_uncompressed_bytes += member.size
            if total_uncompressed_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise SecurityError(
                    f"Archive bomb protection: Total uncompressed size exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES:,} bytes."
                )

        # 5. Overwrite Check
        if not verify_only and os.path.exists(target_path) and not overwrite:
            if member.isreg() or (member.isdir() and not os.path.isdir(target_path)):
                raise FileExistsError(
                    f"Destination file already exists: {target_path}. Specify overwrite=True or --overwrite to proceed."
                )

    # Pass 2: Extraction (if not verify_only)
    if not verify_only:
        os.makedirs(dest_abs, exist_ok=True)
        for member in tar.getmembers():
            raw_name = member.name.replace("\\", "/")
            target_path = os.path.abspath(os.path.join(dest_abs, raw_name))

            if member.isdir():
                os.makedirs(target_path, exist_ok=True)
            elif member.isreg():
                parent_dir = os.path.dirname(target_path)
                if not os.path.exists(parent_dir):
                    os.makedirs(parent_dir, exist_ok=True)

                f_in = tar.extractfile(member)
                if f_in is None:
                    raise IOError(f"Could not read archive entry {member.name}")

                with open(target_path, "wb") as f_out:
                    while True:
                        chunk = f_in.read(65536)
                        if not chunk:
                            break
                        f_out.write(chunk)
                extracted_rel_paths.append(raw_name)
    else:
        for member in tar.getmembers():
            if member.isreg():
                extracted_rel_paths.append(member.name.replace("\\", "/"))

    return extracted_rel_paths


# =====================================================================
# Post-Restoration Manifest Verification
# =====================================================================

def verify_restored_manifest(dest_dir: str) -> Dict[str, Any]:
    """
    Verifies the restored directory against its extracted backup_manifest.json.
    """
    manifest_path = os.path.join(dest_dir, "backup_manifest.json")
    if not os.path.isfile(manifest_path):
        return {"manifest_found": False, "verified": False, "message": "No backup_manifest.json present."}

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # 1. Database check
    db_info = manifest.get("database", {})
    db_path = os.path.join(dest_dir, db_info["file"].replace("/", os.sep))
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"Restored database missing: {db_path}")

    with open(db_path, "rb") as f:
        actual_db_hash = hashlib.sha256(f.read()).hexdigest()
    if actual_db_hash != db_info["sha256"]:
        raise ValueError(f"Restored database hash mismatch! Expected {db_info['sha256']}, got {actual_db_hash}")

    # 2. Documents check
    doc_files = manifest.get("documents", {}).get("files", {})
    verified_docs = 0
    for doc_name, doc_meta in doc_files.items():
        doc_p = os.path.join(dest_dir, "documents", doc_name)
        if not os.path.isfile(doc_p):
            raise FileNotFoundError(f"Restored document missing: {doc_p}")
        with open(doc_p, "rb") as f:
            actual_doc_hash = hashlib.sha256(f.read()).hexdigest()
        if actual_doc_hash != doc_meta["sha256"]:
            raise ValueError(f"Restored document {doc_name} hash mismatch! Expected {doc_meta['sha256']}, got {actual_doc_hash}")
        verified_docs += 1

    return {
        "manifest_found": True,
        "verified": True,
        "database_sha256_matched": True,
        "documents_count_matched": verified_docs,
        "total_documents_expected": len(doc_files)
    }


# =====================================================================
# Main Restoration API
# =====================================================================

def restore_encrypted_backup(
    backup_file: str,
    dest_dir: str,
    passphrase: Optional[str] = None,
    overwrite: bool = False,
    verify_only: bool = False,
    force_backend: Optional[str] = None
) -> Dict[str, Any]:
    """
    Decodes and decrypts a .ktbak archive in memory and safely extracts files into dest_dir.
    """
    backup_file = os.path.abspath(backup_file)
    if not os.path.isfile(backup_file):
        raise FileNotFoundError(f"Backup file not found: {backup_file}")

    with open(backup_file, "rb") as f:
        raw_data = f.read()

    header_info = parse_header(raw_data)

    if passphrase is None:
        passphrase = getpass.getpass("Enter backup passphrase: ")

    key = derive_key(passphrase, header_info["salt"], header_info["iterations"])
    aad = compute_aad(header_info["salt"], header_info["iterations"])

    cipher = get_cipher_engine(key, force_backend=force_backend)
    decrypted_tar_bytes = cipher.decrypt(
        nonce=header_info["nonce"],
        ciphertext=header_info["ciphertext"],
        tag=header_info["tag"],
        associated_data=aad
    )

    # Open tar stream directly from memory
    ram_buf = io.BytesIO(decrypted_tar_bytes)
    with tarfile.open(mode="r:gz", fileobj=ram_buf) as tar:
        extracted_files = safe_extract_tar(
            tar=tar,
            dest_dir=dest_dir,
            overwrite=overwrite,
            verify_only=verify_only
        )

    manifest_check = {}
    if not verify_only:
        manifest_check = verify_restored_manifest(dest_dir)

    return {
        "status": "SUCCESS",
        "archive_file": backup_file,
        "dest_dir": os.path.abspath(dest_dir),
        "files_extracted": len(extracted_files),
        "verify_only": verify_only,
        "manifest_audit": manifest_check,
        "cipher_backend": cipher.__class__.__name__,
        "pbkdf2_iterations": header_info["iterations"]
    }


# =====================================================================
# CLI Entry Point
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="KT Vault V3 - Portable Encrypted Backup Restoration Utility (Zero-Dependency Standalone)"
    )
    parser.add_argument("backup_file", help="Path to encrypted backup (.ktbak) file")
    parser.add_argument("dest_dir", help="Directory where archive contents will be extracted")
    parser.add_argument("--verify-only", action="store_true", help="Decrypt and verify integrity without writing to disk")
    parser.add_argument("--overwrite", action="store_true", help="Permit overwriting existing files in destination")

    args = parser.parse_args()

    try:
        print(f"Reading encrypted backup: {args.backup_file}")
        res = restore_encrypted_backup(
            backup_file=args.backup_file,
            dest_dir=args.dest_dir,
            overwrite=args.overwrite,
            verify_only=args.verify_only
        )
        print("\n=== Backup Decryption and Restoration Complete ===")
        print(f"Status:            {res['status']}")
        print(f"Destination:       {res['dest_dir']}")
        print(f"Files Processed:   {res['files_extracted']}")
        print(f"Verify Only Mode:  {res['verify_only']}")
        print(f"Cipher Backend:    {res['cipher_backend']}")
        print(f"PBKDF2 Iterations: {res['pbkdf2_iterations']:,}")
        if res.get("manifest_audit", {}).get("verified"):
            print(f"Manifest Audit:    PASS (Database matched, {res['manifest_audit']['documents_count_matched']} docs verified)")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Restoration failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
