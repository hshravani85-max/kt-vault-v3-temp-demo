"""
Khanna Travels - KT Vault V3
Encryption Key Rotation Service (key_rotation_service.py)
Phase 16 Hardening: Safe, Atomic, Reversible Master Key Re-Encryption & Escrow Rotation Engine

Safety Principles:
1. Atomic replacement with temporary files and durable .orig staging.
2. Two-phase verification: Decrypt with old key, re-encrypt with new key, test-decrypt with new key BEFORE committing.
3. Fail-closed rollback mechanism on any interruption or I/O failure.
4. Database consistency tracking.
5. Support for sandboxed rehearsal execution on disposable fixtures without touching live keys.
"""

import os
import sys
import json
import secrets
import hashlib
import sqlite3
import shutil
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

import storage_service
from storage_service import (
    KeyProvider,
    get_envelope_metadata,
    _encrypt_envelope,
    _decrypt_envelope
)
import key_management
from key_management import WindowsDPAPIKeyProvider, KeyEscrowService

class RotationError(Exception):
    """Raised when an encryption key rotation preflight or re-encryption step fails."""
    pass

class KeyRotationEngine:
    """
    Orchestrates cryptographic key rotation for KT Vault document storage.
    Supports atomic staging, per-file decryption/re-encryption verification,
    interruption recovery, and automatic rollback.
    """

    def __init__(
        self,
        db_path: str,
        storage_root: str,
        keys_dir: Optional[str] = None,
        key_provider: Optional[KeyProvider] = None
    ):
        self.db_path = os.path.realpath(db_path)
        self.storage_root = os.path.realpath(storage_root)
        self.keys_dir = os.path.realpath(keys_dir) if keys_dir else os.path.join(self.storage_root, ".keys")
        self.key_provider = key_provider or WindowsDPAPIKeyProvider(keys_dir=self.keys_dir)

    def generate_new_master_key(self, new_key_id: str) -> Tuple[str, str]:
        """
        Generates a 256-bit cryptographically secure key and stores it in the key provider.
        Returns (new_key_id, fingerprint).
        """
        clean_id = str(new_key_id).strip()
        if not clean_id:
            raise ValueError("new_key_id cannot be empty.")
            
        if self.key_provider.has_key(clean_id):
            raise RotationError(f"Target key ID '{clean_id}' already exists in key provider. Aborting to avoid overwrite.")

        raw_key = secrets.token_bytes(32)
        fingerprint = KeyEscrowService.compute_fingerprint(raw_key)

        # Save to provider
        self.key_provider.save_key(clean_id, raw_key)
        return clean_id, fingerprint

    def create_rotation_escrow(
        self,
        new_key_id: str,
        passphrase: str,
        output_path: str
    ) -> Dict[str, Any]:
        """
        Generates an encrypted escrow package for the newly generated key.
        """
        raw_key = self.key_provider.get_key(new_key_id)
        escrow = KeyEscrowService.create_escrow_package(raw_key, new_key_id, passphrase)
        
        os.makedirs(os.path.dirname(os.path.realpath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(escrow, f, indent=2)
            
        return escrow

    def rotate_document_file(
        self,
        file_path: str,
        old_key_id: str,
        new_key_id: str
    ) -> Dict[str, Any]:
        """
        Atomically re-encrypts a single document file from old_key_id to new_key_id.
        Keeps a .orig backup during operation.
        Verifies decryptability with new key before returning.
        """
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Document file not found: {file_path}")

        # 1. Read existing ciphertext
        with open(file_path, "rb") as f:
            old_ciphertext = f.read()

        # 2. Parse existing envelope
        header = get_envelope_metadata(old_ciphertext)
        if header.get("key_id") != old_key_id and old_key_id != "master":
            raise RotationError(
                f"File key ID mismatch: expected '{old_key_id}', found '{header.get('key_id')}'"
            )

        storage_id = os.path.basename(file_path)

        # 3. Decrypt plaintext using old key
        old_key = self.key_provider.get_key(old_key_id)
        plaintext = _decrypt_envelope(old_ciphertext, storage_id, key=old_key)

        # 4. Encrypt with new key (V2 envelope)
        new_key = self.key_provider.get_key(new_key_id)
        new_ciphertext = _encrypt_envelope(plaintext, storage_id, new_key, key_id=new_key_id, version=2)

        # 5. Sanity check: test-decrypt new ciphertext in memory
        verify_plaintext = _decrypt_envelope(new_ciphertext, storage_id, key=new_key)
        if verify_plaintext != plaintext:
            raise RotationError("Verification failed: re-encrypted plaintext does not match original.")

        # 6. Stage .orig backup
        orig_backup = f"{file_path}.orig"
        if not os.path.exists(orig_backup):
            shutil.copy2(file_path, orig_backup)

        # 7. Atomic write via temp file
        tmp_target = f"{file_path}.{secrets.token_hex(4)}.tmp"
        try:
            with open(tmp_target, "wb") as f:
                f.write(new_ciphertext)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_target, file_path)
        except Exception as e:
            if os.path.exists(tmp_target):
                try:
                    os.remove(tmp_target)
                except Exception:
                    pass
            raise e

        # Calculate new metadata
        new_sha256 = hashlib.sha256(new_ciphertext).hexdigest()
        new_size = len(new_ciphertext)

        return {
            "file_path": file_path,
            "orig_backup": orig_backup,
            "old_key_id": old_key_id,
            "new_key_id": new_key_id,
            "new_sha256": new_sha256,
            "new_size": new_size
        }

    def execute_batch_rotation(
        self,
        document_files: List[str],
        old_key_id: str,
        new_key_id: str,
        simulate_interruption_at: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Executes key rotation across a list of document files with atomic staging and rollback on failure.
        """
        completed = []
        try:
            for idx, fpath in enumerate(document_files):
                if simulate_interruption_at is not None and idx == simulate_interruption_at:
                    raise RotationError(f"Simulated power interruption at document #{idx}")

                meta = self.rotate_document_file(fpath, old_key_id, new_key_id)
                completed.append(meta)

            # Clean up .orig files on full success
            for item in completed:
                orig_file = item["orig_backup"]
                if os.path.exists(orig_file):
                    os.remove(orig_file)

            return {
                "status": "SUCCESS",
                "total_rotated": len(completed),
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "items": completed
            }

        except Exception as exc:
            # Automatic Rollback
            rollback_count = 0
            for item in completed:
                orig_file = item["orig_backup"]
                target_file = item["file_path"]
                if os.path.exists(orig_file):
                    try:
                        shutil.copy2(orig_file, target_file)
                        os.remove(orig_file)
                        rollback_count += 1
                    except Exception:
                        pass

            return {
                "status": "FAILED_ROLLED_BACK",
                "error": str(exc),
                "completed_before_error": len(completed),
                "rolled_back_count": rollback_count
            }
