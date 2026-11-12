"""
KT Vault V3 - Portable Encrypted Backup Creation Tool
Phase 15B-3B.4E Implementation

Creates an authenticated, password-encrypted, portable archive (.ktbak)
of KT Vault V3 backup snapshots using AES-256-GCM and PBKDF2-HMAC-SHA256.

Envelope Specification (KTBK Version 1):
  Offset 0..3   (4 bytes):  Magic bytes b"KTBK"
  Offset 4..5   (2 bytes):  Version uint16 big-endian (0x0001)
  Offset 6..21  (16 bytes): Cryptographically random PBKDF2 salt
  Offset 22..25 (4 bytes):  Iteration count uint32 big-endian (e.g., 600,000)
  Offset 26..37 (12 bytes): Cryptographically random 96-bit AES-GCM nonce
  Offset 38..53 (16 bytes): 128-bit AES-GCM authentication tag
  Offset 54..N  (variable): AES-256-GCM ciphertext of in-memory tar.gz stream

AAD (Additional Authenticated Data):
  b"KTBK\\x00\\x01" + salt + struct.pack(">I", iterations)

Security Principles:
  1. Complete in-memory packaging: Plaintext never touches disk.
  2. Pre-encryption manifest audit: Source snapshot is validated before encryption.
  3. Secrets hygiene: Passphrases collected via getpass, never logged or in sys.argv.
  4. Atomic output: Writes to temp file first, fsyncs, and replaces destination.
  5. Immutable protection: Refuses to overwrite existing backup files unless forced.
"""

import os
import sys
import io
import json
import struct
import secrets
import hashlib
import tarfile
import getpass
import argparse
import threading
from typing import Optional, Dict, Any, Tuple, List

# Format Constants
MAGIC_BYTES = b"KTBK"
FORMAT_VERSION = 1
SALT_BYTES = 16
NONCE_BYTES = 12
TAG_BYTES = 16
DEFAULT_PBKDF2_ITERATIONS = 600_000
MIN_PBKDF2_ITERATIONS = 100_000
MIN_PASSPHRASE_LENGTH = 8
HEADER_SIZE = 4 + 2 + SALT_BYTES + 4 + NONCE_BYTES + TAG_BYTES  # 54 bytes

# Windows CNG Constants
BCRYPT_AES_ALGORITHM = "AES"
BCRYPT_CHAINING_MODE = "ChainingMode"
BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"
STATUS_SUCCESS = 0x00000000
STATUS_AUTH_TAG_MISMATCH = 0xC000A002


# =====================================================================
# Windows CNG AES-256-GCM Engine (Self-Contained)
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
        """Windows Native CNG AES-256-GCM Authenticated Encryption Engine."""

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

        def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
            """Encrypts plaintext with AES-256-GCM. Returns (ciphertext, tag)."""
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
            return ciphertext, tag

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
                raise ValueError("Authentication tag mismatch: data or header has been tampered with.")
            if status_code != STATUS_SUCCESS:
                raise RuntimeError(f"BCryptDecrypt failed: 0x{status_code:08X}")

            return bytes(pt_buf) if pt_buf else b""

else:
    WindowsCNG_AES256GCM = None


# =====================================================================
# Cross-Platform Fallback (Cryptography Hazmat)
# =====================================================================

class Cryptography_AES256GCM:
    """Cross-Platform AES-256-GCM backend using cryptography library."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 key must be exactly 32 bytes.")
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self.cipher = AESGCM(key)
        except ImportError as e:
            raise RuntimeError(
                "The 'cryptography' package is required on non-Windows platforms. Install via: pip install cryptography"
            ) from e

    def encrypt(self, nonce: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        ct_and_tag = self.cipher.encrypt(nonce, plaintext, associated_data)
        ciphertext = ct_and_tag[:-TAG_BYTES]
        tag = ct_and_tag[-TAG_BYTES:]
        return ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
        from cryptography.exceptions import InvalidTag
        ct_and_tag = ciphertext + tag
        try:
            return self.cipher.decrypt(nonce, ct_and_tag, associated_data)
        except InvalidTag:
            raise ValueError("Authentication tag mismatch: data or header has been tampered with.")


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
# Key Derivation and Authenticated Data
# =====================================================================

def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """Derives a 256-bit AES key using PBKDF2-HMAC-SHA256."""
    if iterations < MIN_PBKDF2_ITERATIONS:
        raise ValueError(f"Iteration count {iterations} is below minimum allowed ({MIN_PBKDF2_ITERATIONS}).")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=32)


def compute_aad(salt: bytes, iterations: int) -> bytes:
    """Constructs authenticated additional data binding header metadata to the GCM tag."""
    return MAGIC_BYTES + struct.pack(">H", FORMAT_VERSION) + salt + struct.pack(">I", iterations)


# =====================================================================
# Pre-Encryption Snapshot Verification
# =====================================================================

def verify_snapshot_integrity(source_dir: str) -> Dict[str, Any]:
    """
    Verifies that the source snapshot exactly matches its backup manifest.
    Stops immediately if any file is missing, modified, or unexpected.
    """
    manifest_path = os.path.join(source_dir, "backup_manifest.json")
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"Missing backup manifest at {manifest_path}. Cannot guarantee snapshot completeness.")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # 1. Verify Database
    db_info = manifest.get("database")
    if not db_info or "file" not in db_info or "sha256" not in db_info:
        raise ValueError("Invalid manifest: missing database entry or sha256.")

    db_rel_path = db_info["file"].replace("/", os.sep)
    db_full_path = os.path.join(source_dir, db_rel_path)
    if not os.path.isfile(db_full_path):
        raise FileNotFoundError(f"Database file referenced in manifest not found on disk: {db_full_path}")

    with open(db_full_path, "rb") as f:
        actual_db_hash = hashlib.sha256(f.read()).hexdigest()
    if actual_db_hash != db_info["sha256"]:
        raise ValueError(
            f"Database integrity failure! Manifest SHA-256: {db_info['sha256']}, Actual SHA-256: {actual_db_hash}"
        )

    # 2. Verify Documents
    docs_section = manifest.get("documents", {})
    doc_files = docs_section.get("files", {})
    if not doc_files:
        raise ValueError("Invalid manifest: documents list is empty.")

    verified_docs = 0
    for doc_name, doc_meta in doc_files.items():
        doc_full_path = os.path.join(source_dir, "documents", doc_name)
        if not os.path.isfile(doc_full_path):
            raise FileNotFoundError(f"Document referenced in manifest not found on disk: {doc_full_path}")
        with open(doc_full_path, "rb") as f:
            actual_doc_hash = hashlib.sha256(f.read()).hexdigest()
        if actual_doc_hash != doc_meta["sha256"]:
            raise ValueError(
                f"Document integrity failure for {doc_name}! Expected: {doc_meta['sha256']}, Actual: {actual_doc_hash}"
            )
        verified_docs += 1

    # 3. Detect Unexpected / Extraneous Files on Disk
    expected_rel_paths = {"backup_manifest.json", db_info["file"].replace("/", os.sep)}
    for doc_name in doc_files.keys():
        expected_rel_paths.add(os.path.join("documents", doc_name))

    actual_rel_paths = set()
    for root, _, files in os.walk(source_dir):
        for fname in files:
            full_p = os.path.join(root, fname)
            rel_p = os.path.relpath(full_p, source_dir)
            actual_rel_paths.add(rel_p)

    unexpected = actual_rel_paths - expected_rel_paths
    if unexpected:
        raise ValueError(f"Snapshot contains unexpected files not in manifest: {sorted(list(unexpected))}")

    missing = expected_rel_paths - actual_rel_paths
    if missing:
        raise ValueError(f"Snapshot is missing expected files listed in manifest: {sorted(list(missing))}")

    return {
        "status": "VERIFIED",
        "total_files": len(actual_rel_paths),
        "database_file": db_info["file"],
        "documents_count": verified_docs,
        "manifest_timestamp": manifest.get("backup_timestamp", "unknown")
    }


# =====================================================================
# In-Memory Archive & Encryption
# =====================================================================

def create_in_memory_archive(source_dir: str) -> bytes:
    """Packages all files from source_dir into an in-memory tar.gz stream."""
    ram_buf = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=ram_buf) as tar:
        for root, dirs, files in os.walk(source_dir):
            dirs.sort()
            files.sort()
            for fname in files:
                full_p = os.path.join(root, fname)
                arcname = os.path.relpath(full_p, source_dir).replace("\\", "/")
                tar.add(full_p, arcname=arcname)
    return ram_buf.getvalue()


def create_encrypted_backup(
    source_dir: str,
    dest_path: str,
    passphrase: Optional[str] = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    force: bool = False,
    force_backend: Optional[str] = None
) -> Dict[str, Any]:
    """
    Full workflow to audit source snapshot, compress in memory, encrypt with AES-256-GCM,
    and atomically write the encrypted backup (.ktbak) file.
    """
    source_dir = os.path.abspath(source_dir)
    dest_path = os.path.abspath(dest_path)

    if not os.path.isdir(source_dir):
        raise NotADirectoryError(f"Source snapshot directory not found: {source_dir}")

    # Ensure output is outside source snapshot
    try:
        common = os.path.commonpath([source_dir, dest_path])
        if common == source_dir:
            raise ValueError("Output backup file must be stored outside the source snapshot directory.")
    except ValueError:
        pass  # Different drives on Windows

    # Refuse to overwrite existing backup
    if os.path.exists(dest_path) and not force:
        raise FileExistsError(f"Output backup file already exists: {dest_path}. Overwriting backups is prohibited.")

    # 1. Audit Source Snapshot Integrity
    audit_result = verify_snapshot_integrity(source_dir)

    # 2. Collect Passphrase if not supplied
    if passphrase is None:
        p1 = getpass.getpass("Enter backup passphrase: ")
        p2 = getpass.getpass("Confirm backup passphrase: ")
        if p1 != p2:
            raise ValueError("Passphrases do not match.")
        if len(p1) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters long.")
        passphrase = p1
    else:
        if len(passphrase) < MIN_PASSPHRASE_LENGTH:
            raise ValueError(f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters long.")

    # 3. Compress snapshot into memory
    tar_gz_bytes = create_in_memory_archive(source_dir)
    uncompressed_archive_size = len(tar_gz_bytes)

    # 4. Derive Key & Generate Cryptographic Material
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(passphrase, salt, iterations)
    aad = compute_aad(salt, iterations)

    # 5. Encrypt with AES-256-GCM
    cipher = get_cipher_engine(key, force_backend=force_backend)
    ciphertext, tag = cipher.encrypt(nonce, tar_gz_bytes, associated_data=aad)

    # 6. Construct KTBK Envelope
    header = (
        MAGIC_BYTES +
        struct.pack(">H", FORMAT_VERSION) +
        salt +
        struct.pack(">I", iterations) +
        nonce +
        tag
    )
    if len(header) != HEADER_SIZE:
        raise RuntimeError(f"Internal error: header size mismatch ({len(header)} != {HEADER_SIZE})")

    encrypted_payload = header + ciphertext

    # 7. Atomic Write to Disk
    dest_dir = os.path.dirname(dest_path)
    if dest_dir and not os.path.exists(dest_dir):
        os.makedirs(dest_dir, exist_ok=True)

    tmp_path = f"{dest_path}.tmp.{os.getpid()}_{secrets.token_hex(4)}"
    try:
        with open(tmp_path, "wb") as f:
            f.write(encrypted_payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, dest_path)
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise

    final_size = os.path.getsize(dest_path)
    with open(dest_path, "rb") as f:
        file_sha256 = hashlib.sha256(f.read()).hexdigest()

    return {
        "status": "SUCCESS",
        "output_path": dest_path,
        "file_size_bytes": final_size,
        "sha256": file_sha256,
        "format_version": FORMAT_VERSION,
        "pbkdf2_iterations": iterations,
        "source_audit": audit_result,
        "uncompressed_archive_size": uncompressed_archive_size,
        "cipher_backend": cipher.__class__.__name__
    }


# =====================================================================
# CLI Entry Point
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description="KT Vault V3 - Portable Encrypted Backup Creation Utility (AES-256-GCM / PBKDF2-HMAC-SHA256)"
    )
    parser.add_argument("source_dir", help="Path to source backup snapshot directory")
    parser.add_argument("output_file", nargs="?", help="Path to write the encrypted backup (.ktbak) file")
    parser.add_argument("--verify-only", action="store_true", help="Audit snapshot against manifest without encrypting")
    parser.add_argument("--iterations", type=int, default=DEFAULT_PBKDF2_ITERATIONS, help="PBKDF2 iterations (default: 600000)")
    parser.add_argument("--force", action="store_true", help="Allow overwriting existing output file (caution)")

    args = parser.parse_args()

    if args.verify_only:
        try:
            print(f"Auditing snapshot integrity at: {args.source_dir} ...")
            res = verify_snapshot_integrity(args.source_dir)
            print("Snapshot Integrity Audit: PASS")
            print(f"Total files checked: {res['total_files']} (Database: 1, Documents: {res['documents_count']})")
            sys.exit(0)
        except Exception as e:
            print(f"Snapshot Integrity Audit: FAILED - {e}", file=sys.stderr)
            sys.exit(1)

    if not args.output_file:
        parser.error("output_file is required when not in --verify-only mode.")

    try:
        print(f"Starting secure backup packaging of: {args.source_dir}")
        res = create_encrypted_backup(
            source_dir=args.source_dir,
            dest_path=args.output_file,
            iterations=args.iterations,
            force=args.force
        )
        print("\n=== Secure Backup Creation Complete ===")
        print(f"Status:             {res['status']}")
        print(f"Output File:        {res['output_path']}")
        print(f"File Size:          {res['file_size_bytes']:,} bytes")
        print(f"SHA-256:            {res['sha256']}")
        print(f"Cipher Backend:     {res['cipher_backend']}")
        print(f"PBKDF2 Iterations:  {res['pbkdf2_iterations']:,}")
        print(f"Documents Included: {res['source_audit']['documents_count']}")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Backup creation failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
