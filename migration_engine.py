"""
KT Vault V3 - Hardened Encryption Migration Engine (migration_engine.py)
Phase 15B-3B.3B: Production Integration of Hardened Document Encryption Migration Service

Architectural Guarantees:
1. Complete Document Verification:
   - Durable trusted baseline manifest with SHA-256 hashes for every unique referenced physical file.
   - Mandatory resolution: every document record MUST resolve to a baseline entry.
   - Strict post-decryption hash comparison against baseline (zero permissive fallbacks).
   - Pre-encrypted files from prior interrupted runs are also decrypted and verified against the baseline hash.
2. Durable Migration Journal & Crash Recovery:
   - State machine: NOT_STARTED -> PREFLIGHT_VERIFIED -> IN_PROGRESS -> FILES_ENCRYPTED -> DB_COMMITTED -> COMPLETED (or ROLLED_BACK).
   - Per-file staging and atomic replacement with .orig backups in .migration_backup/.
   - Automatic rollback on database failure (prevents orphaned encrypted files).
   - Clean resumption or rollback after arbitrary process termination.
3. Strict Path Containment:
   - Every candidate path is strictly validated before reading, writing, replacing, or deleting.
   - Blocks path traversal (..), null bytes, drive boundary crossings, and symbolic-link/reparse escapes.
4. Non-Destructive by Design:
   - Rehearsal and sandbox testing operate strictly against isolated sandbox paths.
   - Live documents and database remain 100% untouched until separate administrator authorization.
"""

import os
import sys
import sqlite3
import hashlib
import json
import secrets
import logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Set

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import storage_service
from storage_service import (
    KeyProvider,
    _encrypt_envelope,
    _decrypt_envelope,
    is_encrypted_bytes,
    read_decrypted_document,
    ENVELOPE_VERSION_V2,
    HEADER_SIZE_V2
)

logger = logging.getLogger("kt_vault.migration")


# =====================================================================
# Exceptions
# =====================================================================

class MigrationPreflightError(Exception):
    """Raised when preflight checks detect missing files, untrusted manifests, or path traversal."""
    pass


class MigrationVerificationError(Exception):
    """Raised when post-encryption verification detects a hash mismatch, missing baseline, or corruption."""
    pass


class MigrationRecoveryError(Exception):
    """Raised when recovery journal detects an inconsistent state or rollback failure."""
    pass


# =====================================================================
# Strict Path Containment & Security
# =====================================================================

def validate_contained_path(candidate_path: str, approved_dir: str) -> str:
    """
    Validates that candidate_path strictly resides within approved_dir:
    1. Rejects None, empty, non-string, or null-byte paths.
    2. Resolves canonical realpath (resolving symlinks, junctions, and relative components).
    3. Confirms approved_dir is a common ancestor via os.path.commonpath.
    4. Rejects symbolic links and junctions escaping outside approved_dir.
    5. Rejects drive boundary crossings on Windows.
    Returns the canonical real path.
    """
    if not candidate_path or not isinstance(candidate_path, str):
        raise ValueError("Storage path must be a non-empty string.")
    if "\0" in candidate_path:
        raise ValueError("Null byte detected in storage path.")

    canonical_dir = os.path.realpath(approved_dir)
    if not os.path.exists(canonical_dir) or not os.path.isdir(canonical_dir):
        raise FileNotFoundError(f"Approved base directory does not exist: '{canonical_dir}'.")

    # If candidate is relative, join with approved_dir
    if os.path.isabs(candidate_path):
        resolved = os.path.realpath(candidate_path)
    else:
        norm = candidate_path.replace("\\", "/")
        parts = norm.split("/")
        if ".." in parts:
            raise PermissionError(f"Access denied: Path traversal sequence '..' in '{candidate_path}'.")
        resolved = os.path.realpath(os.path.join(canonical_dir, candidate_path))

    # Strict containment check
    try:
        common = os.path.commonpath([canonical_dir, resolved])
        if os.path.realpath(common) != canonical_dir:
            raise PermissionError(
                f"Access denied: Path '{candidate_path}' escapes approved directory '{canonical_dir}'."
            )
    except (ValueError, Exception) as e:
        raise PermissionError(f"Access denied: Path validation failure for '{candidate_path}': {e}")

    return resolved


# =====================================================================
# Trusted Baseline Manifest Service
# =====================================================================

class BaselineManifest:
    """
    Manages trusted SHA-256 baseline manifests for document encryption migration.
    Guarantees every database record resolves to a known, verified original hash.
    """

    MANIFEST_VERSION = "KT_VAULT_BASELINE_MANIFEST_V1"

    @classmethod
    def create_manifest(
        cls,
        db_path: str,
        docs_dir: str,
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Builds a trusted baseline manifest from the current state of documents:
        - Resolves every document record in db_path.
        - Calculates SHA-256 for all unique physical files.
        - Validates that unencrypted files can be hashed.
        - Saves to output_path if provided.
        """
        safe_docs_dir = os.path.realpath(docs_dir)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            c = conn.cursor()
            c.execute("SELECT id, requirement_id, file_path FROM documents")
            rows = c.fetchall()
        finally:
            conn.close()

        records_map: Dict[str, List[str]] = {}
        file_hashes: Dict[str, Dict[str, Any]] = {}

        for row in rows:
            doc_id = row["id"]
            raw_path = row["file_path"]

            rel = raw_path
            if rel.startswith("documents\\") or rel.startswith("documents/"):
                rel = rel[10:]

            safe_path = validate_contained_path(rel, safe_docs_dir)
            if not os.path.isfile(safe_path):
                raise MigrationPreflightError(f"Document record '{doc_id}' references missing file: '{safe_path}'.")

            storage_id = os.path.basename(safe_path)
            records_map.setdefault(storage_id, []).append(doc_id)

            if storage_id not in file_hashes:
                with open(safe_path, "rb") as fp:
                    data = fp.read()
                if is_encrypted_bytes(data):
                    raise MigrationPreflightError(
                        f"Cannot create baseline manifest from pre-encrypted file: '{storage_id}'. "
                        "Baseline manifest must be established from original plaintext."
                    )
                file_hashes[storage_id] = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "storage_id": storage_id
                }

        manifest = {
            "format": cls.MANIFEST_VERSION,
            "created_at": datetime.now().isoformat(),
            "total_records": len(rows),
            "unique_files": len(file_hashes),
            "files": file_hashes,
            "records_map": records_map
        }

        if output_path:
            safe_out = os.path.realpath(output_path)
            os.makedirs(os.path.dirname(safe_out), exist_ok=True)
            tmp_out = f"{safe_out}.{secrets.token_hex(4)}.tmp"
            with open(tmp_out, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_out, safe_out)

        return manifest

    @classmethod
    def load_manifest(cls, manifest_path: str) -> Dict[str, Any]:
        """Loads and validates a trusted baseline manifest file."""
        safe_path = os.path.realpath(manifest_path)
        if not os.path.isfile(safe_path):
            raise FileNotFoundError(f"Baseline manifest file not found: '{safe_path}'.")

        with open(safe_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict) or data.get("format") != cls.MANIFEST_VERSION:
            raise MigrationPreflightError(f"Invalid or untrusted manifest format in '{safe_path}'.")

        if "files" not in data or not isinstance(data["files"], dict):
            raise MigrationPreflightError(f"Corrupt manifest: missing 'files' mapping in '{safe_path}'.")

        return data


# =====================================================================
# Durable Migration Journal (Crash Recovery Protocol)
# =====================================================================

class MigrationJournal:
    """
    Durable transactional journal governing filesystem and database synchronization.
    Tracks state machine:
      NOT_STARTED -> PREFLIGHT_OK -> IN_PROGRESS -> FILES_ENCRYPTED -> DB_COMMITTED -> COMPLETED
    Enables guaranteed rollback or resume on arbitrary process termination or DB failure.
    """

    STATE_NOT_STARTED = "NOT_STARTED"
    STATE_PREFLIGHT_OK = "PREFLIGHT_OK"
    STATE_IN_PROGRESS = "IN_PROGRESS"
    STATE_FILES_ENCRYPTED = "FILES_ENCRYPTED"
    STATE_DB_COMMITTED = "DB_COMMITTED"
    STATE_COMPLETED = "COMPLETED"
    STATE_ROLLED_BACK = "ROLLED_BACK"

    def __init__(self, journal_path: str, backup_dir: str):
        self.journal_path = os.path.realpath(journal_path)
        self.backup_dir = os.path.realpath(backup_dir)
        os.makedirs(os.path.dirname(self.journal_path), exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

    def load(self) -> Optional[Dict[str, Any]]:
        if not os.path.isfile(self.journal_path):
            return None
        with open(self.journal_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save(self, data: Dict[str, Any]) -> None:
        tmp_path = f"{self.journal_path}.{secrets.token_hex(4)}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.journal_path)

    def delete(self) -> None:
        if os.path.isfile(self.journal_path):
            try:
                os.remove(self.journal_path)
            except Exception:
                pass


# =====================================================================
# Migration Engine
# =====================================================================

class MigrationEngine:
    """
    Hardened document encryption migration engine for KT Vault V3.
    Enforces complete baseline hash verification, crash recovery journaling,
    strict path containment, and atomic fail-closed operations.
    """

    def __init__(
        self,
        db_path: str,
        docs_dir: str,
        key_provider: KeyProvider,
        key_id: str = "ktv_2026_v1",
        envelope_version: int = ENVELOPE_VERSION_V2,
        manifest_path: Optional[str] = None,
        journal_path: Optional[str] = None
    ):
        self.db_path = os.path.realpath(db_path)
        self.docs_dir = os.path.realpath(docs_dir)
        self.key_provider = key_provider
        self.key_id = str(key_id).strip()
        self.envelope_version = envelope_version

        if len(self.key_id) > 16:
            raise ValueError(f"key_id '{self.key_id}' exceeds maximum length of 16 bytes.")

        if not os.path.isfile(self.db_path):
            raise FileNotFoundError(f"Database does not exist: '{self.db_path}'.")
        if not os.path.isdir(self.docs_dir):
            raise FileNotFoundError(f"Documents directory does not exist: '{self.docs_dir}'.")

        if not self.key_provider.has_key(self.key_id):
            raise RuntimeError(f"Encryption key '{self.key_id}' is not available in the key provider.")

        # Durable journal and backup directory configuration
        self.journal_path = journal_path or os.path.join(self.docs_dir, ".migration_journal.json")
        self.backup_dir = os.path.join(self.docs_dir, ".migration_backup")
        self.journal = MigrationJournal(self.journal_path, self.backup_dir)

        # Baseline manifest path
        self.manifest_path = manifest_path or os.path.join(self.docs_dir, ".baseline_manifest.json")

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def establish_or_load_manifest(self) -> Dict[str, Any]:
        """Loads existing baseline manifest or establishes a new one from plaintext documents."""
        if os.path.isfile(self.manifest_path):
            return BaselineManifest.load_manifest(self.manifest_path)
        return BaselineManifest.create_manifest(self.db_path, self.docs_dir, self.manifest_path)

    def preflight_check(self) -> Dict[str, Any]:
        """
        Executes exhaustive preflight validation:
        1. Loads/verifies trusted baseline manifest.
        2. Validates path containment for every document record.
        3. Rejects missing files, untrusted files, path traversal, or symlink escapes.
        4. Identifies shared physical files.
        5. Confirms key availability.
        """
        manifest = self.establish_or_load_manifest()
        manifest_files = manifest["files"]

        conn = self._get_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT id, requirement_id, status, file_path FROM documents")
            doc_rows = c.fetchall()
        finally:
            conn.close()

        records = []
        path_to_records: Dict[str, List[str]] = {}
        missing_files = []
        already_encrypted = []
        untrusted_files = []

        for row in doc_rows:
            doc_id = row["id"]
            raw_path = row["file_path"]

            rel = raw_path
            if rel.startswith("documents\\") or rel.startswith("documents/"):
                rel = rel[10:]

            # Strict path containment check
            safe_path = validate_contained_path(rel, self.docs_dir)
            storage_id = os.path.basename(safe_path)

            if not os.path.isfile(safe_path):
                missing_files.append({"doc_id": doc_id, "file": storage_id, "path": safe_path})
                continue

            # Must exist in trusted baseline manifest
            if storage_id not in manifest_files:
                untrusted_files.append({"doc_id": doc_id, "file": storage_id})

            records.append({
                "doc_id": doc_id,
                "requirement_id": row["requirement_id"],
                "raw_path": raw_path,
                "canonical_path": safe_path,
                "storage_id": storage_id
            })

            path_to_records.setdefault(safe_path, []).append(doc_id)

            with open(safe_path, "rb") as fp:
                head = fp.read(4)
            if head in (b"KTV1", b"KTV2"):
                already_encrypted.append(safe_path)

        if missing_files:
            raise MigrationPreflightError(
                f"Preflight failed: {len(missing_files)} document records reference missing files: {missing_files}"
            )

        if untrusted_files:
            raise MigrationPreflightError(
                f"Preflight failed: {len(untrusted_files)} documents not found in trusted baseline manifest: {untrusted_files}"
            )

        # Confirm all unique files in manifest are accounted for
        manifest_unique_count = len(manifest_files)
        if len(path_to_records) != manifest_unique_count:
            raise MigrationPreflightError(
                f"Manifest mismatch: Database references {len(path_to_records)} unique files, "
                f"but manifest contains {manifest_unique_count} files."
            )

        shared_files = {p: recs for p, recs in path_to_records.items() if len(recs) > 1}

        # Check for unreferenced files in docs_dir
        all_disk_files = {
            os.path.realpath(os.path.join(self.docs_dir, f))
            for f in os.listdir(self.docs_dir)
            if os.path.isfile(os.path.join(self.docs_dir, f)) and not f.startswith(".")
        }
        referenced_disk_files = set(path_to_records.keys())
        unreferenced_files = sorted(list(all_disk_files - referenced_disk_files))

        # Build plaintext_hashes mapping (canonical_path -> baseline sha256) for backward compatibility
        plaintext_hashes = {
            p: manifest_files[os.path.basename(p)]["sha256"]
            for p in path_to_records.keys()
            if os.path.basename(p) in manifest_files
        }

        return {
            "total_records": len(records),
            "unique_referenced_files": len(path_to_records),
            "shared_physical_files": len(shared_files),
            "shared_mapping": shared_files,
            "already_encrypted_count": len(already_encrypted),
            "plaintext_files_to_encrypt": len(path_to_records) - len(already_encrypted),
            "unreferenced_files_count": len(unreferenced_files),
            "unreferenced_files": [os.path.basename(p) for p in unreferenced_files],
            "plaintext_hashes": plaintext_hashes,
            "path_to_records": path_to_records,
            "manifest": manifest
        }

    def run_dry_run(self) -> Dict[str, Any]:
        """
        Executes a dry-run simulation of the migration:
        - Performs all preflight checks and loads/verifies trusted baseline manifest.
        - Simulates envelope creation for each unique file in memory.
        - Simulates decryption and verifies simulated decrypted hash matches baseline hash.
        - Does NOT write to disk or database.
        """
        preflight = self.preflight_check()
        key = self.key_provider.get_key(self.key_id)

        simulated_files = 0
        for canonical_path, expected_hash in preflight["plaintext_hashes"].items():
            storage_id = os.path.basename(canonical_path)
            with open(canonical_path, "rb") as f:
                plain = f.read()

            # If file is already encrypted, decrypt and verify
            if is_encrypted_bytes(plain):
                decrypted = _decrypt_envelope(
                    plain,
                    storage_id,
                    key_provider=self.key_provider
                )
            else:
                # Simulate encryption
                envelope = _encrypt_envelope(
                    plain,
                    storage_id,
                    key,
                    key_id=self.key_id,
                    version=self.envelope_version
                )
                # Simulate decryption
                decrypted = _decrypt_envelope(
                    envelope,
                    storage_id,
                    key_provider=self.key_provider
                )

            if hashlib.sha256(decrypted).hexdigest() != expected_hash:
                raise MigrationVerificationError(
                    f"Dry run failed: Simulated decrypted hash mismatch for '{canonical_path}'."
                )
            simulated_files += 1

        return {
            "status": "dry_run_success",
            "preflight": preflight,
            "simulated_files_verified": simulated_files
        }

    def execute_migration(
        self,
        stop_after_n_files: Optional[int] = None,
        simulate_db_failure: bool = False
    ) -> Dict[str, Any]:
        """
        Executes the hardened in-place document encryption migration with durable journaling:
        1. Preflight validation & manifest verification.
        2. Initializes durable migration journal and .orig staging backups.
        3. Encrypts unique files atomically with pre-commit hash verification against baseline.
        4. Fails closed with automatic rollback if database transaction fails.
        5. Verifies all records against baseline manifest post-migration.
        """
        preflight = self.preflight_check()
        manifest = preflight["manifest"]
        manifest_files = manifest["files"]
        key = self.key_provider.get_key(self.key_id)

        unique_paths = sorted(list(preflight["path_to_records"].keys()))

        # Check existing journal
        j_data = self.journal.load()
        if j_data and j_data.get("state") == MigrationJournal.STATE_COMPLETED:
            logger.info("Migration was already completed according to durable journal.")
            return {
                "status": "success",
                "encrypted_count": 0,
                "skipped_count": len(unique_paths),
                "total_unique_files": len(unique_paths),
                "verification": self.verify_all_documents(manifest)
            }

        # Initialize or update journal
        if not j_data:
            j_data = {
                "state": MigrationJournal.STATE_IN_PROGRESS,
                "key_id": self.key_id,
                "envelope_version": self.envelope_version,
                "total_files": len(unique_paths),
                "files": {
                    os.path.basename(p): {
                        "canonical_path": p,
                        "backup_path": os.path.join(self.backup_dir, f"{os.path.basename(p)}.orig"),
                        "baseline_hash": manifest_files[os.path.basename(p)]["sha256"],
                        "status": "PENDING"
                    }
                    for p in unique_paths
                }
            }
            self.journal.save(j_data)

        encrypted_count = 0
        skipped_count = 0

        for path in unique_paths:
            sid = os.path.basename(path)
            entry = j_data["files"][sid]

            # Interruption simulation hook
            if stop_after_n_files is not None and encrypted_count >= stop_after_n_files:
                logger.warning("Interrupted migration simulation triggered after %d files.", encrypted_count)
                return {
                    "status": "interrupted",
                    "encrypted_count": encrypted_count,
                    "skipped_count": skipped_count,
                    "remaining": len(unique_paths) - (encrypted_count + skipped_count)
                }

            # Check if journal already recorded this file as encrypted
            if entry["status"] == "ENCRYPTED":
                skipped_count += 1
                continue

            with open(path, "rb") as fp:
                data = fp.read()

            expected_hash = entry["baseline_hash"]

            # If file on disk is already encrypted, verify its decrypted hash matches baseline
            if is_encrypted_bytes(data):
                decrypted = _decrypt_envelope(data, sid, key_provider=self.key_provider)
                if hashlib.sha256(decrypted).hexdigest() != expected_hash:
                    raise MigrationVerificationError(
                        f"Pre-encrypted file '{sid}' failed baseline hash verification."
                    )
                entry["status"] = "ENCRYPTED"
                self.journal.save(j_data)
                skipped_count += 1
                continue

            # Verify plaintext before encryption matches baseline hash
            actual_plain_hash = hashlib.sha256(data).hexdigest()
            if actual_plain_hash != expected_hash:
                raise MigrationVerificationError(
                    f"Plaintext file '{sid}' hash {actual_plain_hash} does not match baseline {expected_hash}!"
                )

            # Stage .orig backup for crash recovery
            backup_path = entry["backup_path"]
            if not os.path.exists(backup_path):
                tmp_bak = f"{backup_path}.{secrets.token_hex(4)}.tmp"
                with open(tmp_bak, "wb") as f_bak:
                    f_bak.write(data)
                    f_bak.flush()
                    os.fsync(f_bak.fileno())
                os.replace(tmp_bak, backup_path)

            # Encrypt to KTV2 envelope
            envelope = _encrypt_envelope(
                data,
                sid,
                key,
                key_id=self.key_id,
                version=self.envelope_version
            )

            # Pre-commit self-verification against baseline
            decrypted = _decrypt_envelope(envelope, sid, key_provider=self.key_provider)
            if hashlib.sha256(decrypted).hexdigest() != expected_hash:
                raise MigrationVerificationError(
                    f"Self-verification failed for '{sid}': Decrypted bytes mismatch baseline!"
                )

            # Atomic replace
            temp_path = f"{path}.{secrets.token_hex(4)}.tmp"
            try:
                with open(temp_path, "wb") as f_tmp:
                    f_tmp.write(envelope)
                    f_tmp.flush()
                    os.fsync(f_tmp.fileno())
                os.replace(temp_path, path)
            except Exception as e:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                raise e

            # Update journal entry
            entry["status"] = "ENCRYPTED"
            self.journal.save(j_data)
            encrypted_count += 1

        # All files encrypted on disk
        j_data["state"] = MigrationJournal.STATE_FILES_ENCRYPTED
        self.journal.save(j_data)

        # Database Audit Transaction with automatic rollback on failure
        conn = self._get_connection()
        try:
            if simulate_db_failure:
                raise sqlite3.OperationalError("Simulated database failure during audit commit.")

            audit_desc = (
                f"Document Encryption Migration completed: {encrypted_count} files encrypted, "
                f"{skipped_count} skipped under key_id '{self.key_id}' (KTV2)."
            )
            conn.execute(
                "INSERT INTO activity (trip_id, customer_id, description) VALUES (?, ?, ?)",
                ("TRIP-MIGRATE", "CUST-SYSTEM", audit_desc)
            )
            conn.commit()
            j_data["state"] = MigrationJournal.STATE_DB_COMMITTED
            self.journal.save(j_data)
        except Exception as e:
            if conn.in_transaction:
                conn.rollback()
            conn.close()
            logger.error("Database transaction failed! Triggering automatic filesystem rollback: %s", str(e))
            self.rollback_migration()
            raise e
        finally:
            conn.close()

        # Comprehensive post-migration verification against baseline manifest
        verification_result = self.verify_all_documents(manifest)

        # Mark completed and clean up staging backups
        j_data["state"] = MigrationJournal.STATE_COMPLETED
        self.journal.save(j_data)
        self.cleanup_staging_backups()

        return {
            "status": "success",
            "encrypted_count": encrypted_count,
            "skipped_count": skipped_count,
            "total_unique_files": len(unique_paths),
            "verification": verification_result
        }

    def rollback_migration(self) -> Dict[str, Any]:
        """
        Rolls back all encrypted files to their original plaintext state using .orig backups.
        Guarantees zero data loss or corrupted files if migration fails or is aborted.
        """
        j_data = self.journal.load()
        if not j_data or "files" not in j_data:
            return {"status": "no_journal_to_rollback"}

        restored_count = 0
        failures = []

        for sid, entry in j_data["files"].items():
            path = entry["canonical_path"]
            backup_path = entry["backup_path"]
            baseline_hash = entry["baseline_hash"]

            if os.path.isfile(backup_path):
                # Verify backup file hash matches baseline
                with open(backup_path, "rb") as fb:
                    bak_data = fb.read()
                if hashlib.sha256(bak_data).hexdigest() != baseline_hash:
                    failures.append({"file": sid, "error": "Backup file hash corrupt!"})
                    continue

                # Restore original file atomically
                tmp_rest = f"{path}.{secrets.token_hex(4)}.tmp"
                with open(tmp_rest, "wb") as f_r:
                    f_r.write(bak_data)
                    f_r.flush()
                    os.fsync(f_r.fileno())
                os.replace(tmp_rest, path)

                # Verify restored file
                with open(path, "rb") as fp:
                    if hashlib.sha256(fp.read()).hexdigest() == baseline_hash:
                        restored_count += 1
                        entry["status"] = "RESTORED"
                    else:
                        failures.append({"file": sid, "error": "Restored file hash mismatch!"})

        j_data["state"] = MigrationJournal.STATE_ROLLED_BACK
        self.journal.save(j_data)

        if failures:
            raise MigrationRecoveryError(f"Rollback encountered failures: {failures}")

        self.cleanup_staging_backups()
        self.journal.delete()

        return {
            "status": "rolled_back",
            "restored_count": restored_count
        }

    def resume_migration(self) -> Dict[str, Any]:
        """Resumes an interrupted migration from the durable journal state."""
        j_data = self.journal.load()
        if not j_data or j_data.get("state") not in (
            MigrationJournal.STATE_IN_PROGRESS,
            MigrationJournal.STATE_FILES_ENCRYPTED
        ):
            return self.execute_migration()

        # Resume execution
        return self.execute_migration()

    def cleanup_staging_backups(self) -> None:
        """Safely removes temporary .orig backup files and staging directory."""
        if os.path.isdir(self.backup_dir):
            for f in os.listdir(self.backup_dir):
                if f.endswith(".orig") or f.endswith(".tmp"):
                    try:
                        os.remove(os.path.join(self.backup_dir, f))
                    except Exception:
                        pass
            try:
                os.rmdir(self.backup_dir)
            except Exception:
                pass

    def verify_all_documents(self, expected_hashes: Optional[Any] = None) -> Dict[str, Any]:
        """
        Comprehensive post-migration verification:
        1. Queries every document record in the database.
        2. Validates path containment.
        3. Decrypts via storage_service.read_decrypted_document.
        4. Strictly validates decrypted bytes against baseline manifest SHA-256 hash.
        5. Fails closed: Rejects unknown files, missing hashes, or mismatches.

        Supports passing either:
        - None (loads or establishes the trusted BaselineManifest)
        - A BaselineManifest dictionary with 'files' key
        - A dictionary of {path_or_storage_id: sha256_hash} for backward compatibility
        """
        if expected_hashes is None:
            target_manifest = self.establish_or_load_manifest()
            manifest_files = target_manifest["files"]
        elif isinstance(expected_hashes, dict) and "files" in expected_hashes and isinstance(expected_hashes["files"], dict):
            target_manifest = expected_hashes
            manifest_files = target_manifest["files"]
        elif isinstance(expected_hashes, dict):
            # Dict mapping path or storage_id -> sha256 string
            manifest_files = {}
            for k, v in expected_hashes.items():
                storage_id = os.path.basename(k)
                if isinstance(v, dict) and "sha256" in v:
                    manifest_files[storage_id] = v
                elif isinstance(v, str):
                    manifest_files[storage_id] = {"sha256": v, "storage_id": storage_id}
                else:
                    raise MigrationVerificationError(f"Invalid hash entry format for '{k}': {v}")
        else:
            raise MigrationVerificationError("Invalid manifest / expected_hashes argument provided.")

        conn = self._get_connection()
        try:
            c = conn.cursor()
            c.execute("SELECT id, requirement_id, file_path FROM documents")
            records = c.fetchall()
        finally:
            conn.close()

        verified_records = 0
        failures = []

        for row in records:
            doc_id = row["id"]
            raw_path = row["file_path"]

            rel = raw_path
            if rel.startswith("documents\\") or rel.startswith("documents/"):
                rel = rel[10:]

            # Path containment check
            try:
                safe_path = validate_contained_path(rel, self.docs_dir)
            except Exception as e:
                failures.append({"doc_id": doc_id, "error": f"Path containment violation: {e}"})
                continue

            storage_id = os.path.basename(safe_path)

            # Strict manifest requirement: Missing hash is an IMMEDIATE failure
            if storage_id not in manifest_files:
                failures.append({
                    "doc_id": doc_id,
                    "file": storage_id,
                    "error": "Document storage_id not present in trusted baseline manifest!"
                })
                continue

            expected_hash = manifest_files[storage_id].get("sha256")
            if not expected_hash:
                failures.append({
                    "doc_id": doc_id,
                    "file": storage_id,
                    "error": "Trusted baseline manifest missing sha256 hash for document!"
                })
                continue

            try:
                decrypted_bytes = read_decrypted_document(
                    safe_path,
                    file_storage_id=storage_id,
                    key_provider=self.key_provider,
                    base_dir=self.docs_dir,
                    system_context=True
                )
                actual_hash = hashlib.sha256(decrypted_bytes).hexdigest()

                if actual_hash != expected_hash:
                    failures.append({
                        "doc_id": doc_id,
                        "file": storage_id,
                        "error": f"Hash mismatch: actual {actual_hash} != baseline {expected_hash}"
                    })
                else:
                    verified_records += 1
            except Exception as e:
                failures.append({
                    "doc_id": doc_id,
                    "file": storage_id,
                    "error": f"Decryption failure: {str(e)}"
                })

        if failures:
            raise MigrationVerificationError(
                f"Post-migration verification failed for {len(failures)} records: {failures}"
            )

        return {
            "verified_records_count": verified_records,
            "total_records": len(records),
            "all_verified": True
        }


# Backwards compatibility alias
HardenedMigrationEngine = MigrationEngine
