"""
Khanna Travels - KT Vault V3
Independent Off-Site Backup & Disaster Recovery Service (offsite_backup_service.py)
Phase 16 Hardening: Provider-Agnostic Off-Site Storage Adapter, WORM Immutability & Disaster Recovery Harness

Architecture & Safety Principles:
1. Local drive backups (e.g. C:\\KT_Vault_Backup_Safe) are strictly LOCAL redundancy, NOT off-site disaster recovery.
2. Independent off-site backups require physically separated, credential-isolated object storage.
3. WORM (Write Once Read Many) / Object Lock protects against ransomware and unauthorized deletion.
4. Separate lifecycle for application backups (.ktbak) and master key escrow packages.
5. Provider-independent interface allows seamless plug-in for AWS S3 Object Lock, Azure Immutable Blob, or local simulation.
"""

import os
import sys
import json
import hashlib
import time
import shutil
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, BinaryIO

class BackupError(Exception):
    """Base exception for off-site backup operations."""
    pass

class ImmutabilityViolationError(BackupError):
    """Raised when an attempt is made to overwrite or prematurely delete an immutable backup."""
    pass

class OffsiteStorageProvider:
    """
    Abstract interface for off-site backup repositories.
    Provides standard methods for uploading, verifying, listing, and downloading backups.
    """
    def upload_backup(
        self,
        backup_name: str,
        backup_stream: BinaryIO,
        sha256_checksum: str,
        retention_days: int = 90
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def download_backup(self, backup_name: str, destination_path: str) -> str:
        raise NotImplementedError

    def verify_backup_integrity(self, backup_name: str, expected_sha256: str) -> bool:
        raise NotImplementedError

    def list_backups(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def delete_backup(self, backup_name: str) -> bool:
        raise NotImplementedError


class LocalSimulatedCloudStorage(OffsiteStorageProvider):
    """
    Simulates a compliant Cloud Object Storage bucket (e.g. AWS S3 with Object Lock Compliance Mode).
    Enforces WORM immutability, retention expiration, and SHA-256 verification in a local sandboxed directory.
    Enables thorough automated testing of off-site disaster recovery without paying for cloud resources.
    """

    def __init__(self, bucket_root: str):
        self.bucket_root = os.path.realpath(bucket_root)
        self.metadata_file = os.path.join(self.bucket_root, ".bucket_catalog.json")
        os.makedirs(self.bucket_root, exist_ok=True)
        self._load_catalog()

    def _load_catalog(self):
        if os.path.exists(self.metadata_file):
            try:
                with open(self.metadata_file, "r", encoding="utf-8") as f:
                    self.catalog = json.load(f)
            except Exception:
                self.catalog = {}
        else:
            self.catalog = {}

    def _save_catalog(self):
        with open(self.metadata_file, "w", encoding="utf-8") as f:
            json.dump(self.catalog, f, indent=2)

    def upload_backup(
        self,
        backup_name: str,
        backup_bytes: bytes,
        sha256_checksum: str,
        retention_days: int = 90
    ) -> Dict[str, Any]:
        """
        Stores an encrypted backup with immutable lock until retain_until_date.
        Prevents overwriting existing object (WORM enforcement).
        """
        clean_name = os.path.basename(backup_name)
        target_path = os.path.join(self.bucket_root, clean_name)

        # Check immutability
        if clean_name in self.catalog or os.path.exists(target_path):
            raise ImmutabilityViolationError(
                f"WORM Violation: Backup '{clean_name}' already exists in immutable storage. Overwrite rejected."
            )

        # Verify integrity before persisting
        computed_sha256 = hashlib.sha256(backup_bytes).hexdigest()
        if computed_sha256.lower() != sha256_checksum.lower():
            raise BackupError(
                f"Integrity check failed: Expected {sha256_checksum}, got {computed_sha256}"
            )

        now = datetime.now(timezone.utc)
        retain_until = (now + timedelta(days=retention_days)).isoformat()

        # Persist bytes
        with open(target_path, "wb") as f:
            f.write(backup_bytes)

        # Record catalog entry with object lock
        record = {
            "name": clean_name,
            "size": len(backup_bytes),
            "sha256": computed_sha256,
            "uploaded_at": now.isoformat(),
            "retain_until": retain_until,
            "object_lock_mode": "COMPLIANCE",
            "immutability_status": "LOCKED"
        }
        self.catalog[clean_name] = record
        self._save_catalog()

        return record

    def download_backup(self, backup_name: str, destination_path: str) -> str:
        clean_name = os.path.basename(backup_name)
        source_path = os.path.join(self.bucket_root, clean_name)
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Backup '{clean_name}' not found in off-site storage.")

        os.makedirs(os.path.dirname(os.path.realpath(destination_path)), exist_ok=True)
        with open(source_path, "rb") as src, open(destination_path, "wb") as dst:
            shutil.copyfileobj(src, dst)

        return destination_path

    def verify_backup_integrity(self, backup_name: str, expected_sha256: str) -> bool:
        clean_name = os.path.basename(backup_name)
        source_path = os.path.join(self.bucket_root, clean_name)
        if not os.path.exists(source_path):
            return False

        h = hashlib.sha256()
        with open(source_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)

        return h.hexdigest().lower() == expected_sha256.lower()

    def list_backups(self) -> List[Dict[str, Any]]:
        self._load_catalog()
        return list(self.catalog.values())

    def delete_backup(self, backup_name: str) -> bool:
        """Enforces WORM retention policy: cannot delete while locked."""
        clean_name = os.path.basename(backup_name)
        if clean_name not in self.catalog:
            return False

        item = self.catalog[clean_name]
        retain_until = datetime.fromisoformat(item["retain_until"])
        now = datetime.now(timezone.utc)

        if now < retain_until:
            raise ImmutabilityViolationError(
                f"WORM Retention Active: Backup '{clean_name}' is locked in COMPLIANCE mode until {retain_until}. Deletion blocked."
            )

        source_path = os.path.join(self.bucket_root, clean_name)
        if os.path.exists(source_path):
            os.remove(source_path)
        del self.catalog[clean_name]
        self._save_catalog()
        return True


class S3ObjectLockStorageAdapter(OffsiteStorageProvider):
    """
    Production AWS S3 / Cloudian / MinIO storage adapter utilizing S3 Object Lock (WORM).
    Requires external cloud provisioning and IAM credentials.
    """
    def __init__(
        self,
        bucket_name: str,
        region: str = "ap-south-1",
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        endpoint_url: Optional[str] = None
    ):
        self.bucket_name = bucket_name
        self.region = region
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.endpoint_url = endpoint_url

    def is_configured(self) -> bool:
        return bool(self.bucket_name and self.access_key_id and self.secret_access_key)

    def upload_backup(
        self,
        backup_name: str,
        backup_stream: BinaryIO,
        sha256_checksum: str,
        retention_days: int = 90
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise NotImplementedError(
                "S3 Object Lock storage adapter is not configured. "
                "Requires AWS_S3_BUCKET, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY."
            )
        raise NotImplementedError("Live cloud communication blocked until external provisioning.")

    def download_backup(self, backup_name: str, destination_path: str) -> str:
        raise NotImplementedError("Live cloud communication blocked.")

    def verify_backup_integrity(self, backup_name: str, expected_sha256: str) -> bool:
        raise NotImplementedError("Live cloud communication blocked.")

    def list_backups(self) -> List[Dict[str, Any]]:
        return []

    def delete_backup(self, backup_name: str) -> bool:
        raise NotImplementedError("Cloud deletion blocked by Object Lock Compliance policy.")


class AzureImmutableBlobStorageAdapter(OffsiteStorageProvider):
    """
    Production Azure Blob Storage adapter with Immutable Blob Storage (WORM).
    Supports Time-Based Retention policies (locked/unlocked) and Legal Hold immutability.
    Requires external Azure Storage provisioning, container creation, and access credentials.
    """
    def __init__(
        self,
        account_name: Optional[str] = None,
        container_name: Optional[str] = None,
        connection_string: Optional[str] = None,
        account_key: Optional[str] = None,
        sas_token: Optional[str] = None,
        immutability_policy: str = "time_based",
        retention_days: int = 90
    ):
        self.account_name = account_name or os.environ.get("AZURE_STORAGE_ACCOUNT")
        self.container_name = container_name or os.environ.get("AZURE_STORAGE_CONTAINER")
        self.connection_string = connection_string or os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
        self.account_key = account_key or os.environ.get("AZURE_STORAGE_KEY")
        self.sas_token = sas_token or os.environ.get("AZURE_STORAGE_SAS_TOKEN")
        self.immutability_policy = immutability_policy
        self.retention_days = retention_days

    def is_configured(self) -> bool:
        has_auth = bool(self.connection_string or (self.account_name and (self.account_key or self.sas_token)))
        return bool(self.container_name and has_auth)

    def upload_backup(
        self,
        backup_name: str,
        backup_stream: BinaryIO,
        sha256_checksum: str,
        retention_days: int = 90
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise NotImplementedError(
                "Azure Immutable Blob storage adapter is not configured. "
                "Requires AZURE_STORAGE_ACCOUNT and AZURE_STORAGE_KEY (or AZURE_STORAGE_CONNECTION_STRING) "
                "and AZURE_STORAGE_CONTAINER."
            )
        raise NotImplementedError("Live Azure communication blocked until external cloud provisioning.")

    def download_backup(self, backup_name: str, destination_path: str) -> str:
        raise NotImplementedError("Live Azure communication blocked until external cloud provisioning.")

    def verify_backup_integrity(self, backup_name: str, expected_sha256: str) -> bool:
        raise NotImplementedError("Live Azure communication blocked until external cloud provisioning.")

    def list_backups(self) -> List[Dict[str, Any]]:
        return []

    def delete_backup(self, backup_name: str) -> bool:
        raise NotImplementedError(
            "Azure Blob deletion blocked by WORM Time-Based Retention / Legal Hold policy."
        )


def get_offsite_provider(provider_type: Optional[str] = None, **kwargs) -> OffsiteStorageProvider:
    """
    Factory to instantiate the appropriate off-site storage adapter based on configuration.
    Defaults to LocalSimulatedCloudStorage for local safety and zero cloud dependency.
    """
    provider = (provider_type or os.environ.get("KT_OFFSITE_STORAGE_PROVIDER", "simulated")).lower()
    
    if provider == "azure":
        return AzureImmutableBlobStorageAdapter(**kwargs)
    elif provider in ("s3", "aws"):
        return S3ObjectLockStorageAdapter(
            bucket_name=kwargs.get("bucket_name") or os.environ.get("AWS_S3_BUCKET", ""),
            region=kwargs.get("region") or os.environ.get("AWS_REGION", "ap-south-1"),
            access_key_id=kwargs.get("access_key_id") or os.environ.get("AWS_ACCESS_KEY_ID"),
            secret_access_key=kwargs.get("secret_access_key") or os.environ.get("AWS_SECRET_ACCESS_KEY"),
            endpoint_url=kwargs.get("endpoint_url") or os.environ.get("AWS_S3_ENDPOINT_URL")
        )
    else:
        bucket_dir = kwargs.get("bucket_root") or os.environ.get(
            "KT_SIMULATED_OFFSITE_DIR",
            os.path.join(os.path.dirname(__file__), "backups", "simulated_cloud")
        )
        return LocalSimulatedCloudStorage(bucket_root=bucket_dir)

