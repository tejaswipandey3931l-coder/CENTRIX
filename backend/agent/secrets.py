"""Tenant-isolated encrypted secret management for CENTRIX.

Provides authenticated encryption for sensitive credentials (BYO AI provider keys,
tokens, auth headers) per tenant/organization. Secrets are never exposed in plaintext
in logs, error messages, or reports.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from db.store import _connection, _get_lock, _init_db


# Master secret configuration
_MASTER_KEY_ENV = "CENTRIX_MASTER_KEY"
_DEFAULT_SALT = b"centrix_tenant_secret_salt_v1"


def _derive_key(secret: str, salt: bytes = _DEFAULT_SALT) -> bytes:
    """Derive a URL-safe base64-encoded 32-byte key via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode("utf-8")))


class SecretManager:
    """Encrypted secret vault with organization/tenant isolation."""

    def __init__(self, master_key: Optional[str] = None):
        raw_key = master_key or os.getenv(_MASTER_KEY_ENV) or "centrix-default-platform-master-key-2026"
        self._fernet = Fernet(_derive_key(raw_key))
        self._init_table()

    def _init_table(self) -> None:
        _init_db()
        with _connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_secrets (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    secret_name TEXT NOT NULL,
                    encrypted_value TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(organization_id, secret_name)
                );
            """)

    def set_secret(
        self,
        organization_id: str,
        secret_name: str,
        plaintext_value: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """Encrypt and persist a secret for a specific organization/tenant."""
        if not organization_id or not secret_name:
            raise ValueError("organization_id and secret_name must be non-empty strings")
        
        encrypted = self._fernet.encrypt(plaintext_value.encode("utf-8")).decode("ascii")
        meta_str = json.dumps(metadata or {})
        now = datetime.utcnow().isoformat()
        secret_id = f"sec-{uuid.uuid4().hex[:10]}"

        with _connection() as conn:
            conn.execute("""
                INSERT INTO tenant_secrets (id, organization_id, secret_name, encrypted_value, metadata, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(organization_id, secret_name) DO UPDATE SET
                    encrypted_value = excluded.encrypted_value,
                    metadata = excluded.metadata,
                    updated_at = excluded.updated_at
            """, (secret_id, organization_id, secret_name, encrypted, meta_str, now))
        
        return secret_id

    def get_secret(self, organization_id: str, secret_name: str) -> Optional[str]:
        """Retrieve and decrypt a tenant secret. Returns None if not found."""
        with _connection() as conn:
            row = conn.execute(
                "SELECT encrypted_value FROM tenant_secrets WHERE organization_id = ? AND secret_name = ?",
                (organization_id, secret_name),
            ).fetchone()
        
        if not row:
            return None
        
        try:
            decrypted = self._fernet.decrypt(row["encrypted_value"].encode("ascii"))
            return decrypted.decode("utf-8")
        except Exception as exc:
            raise RuntimeError(f"Failed to decrypt secret '{secret_name}' for tenant '{organization_id}': {exc}")

    def list_secrets(self, organization_id: str) -> list[dict[str, Any]]:
        """List metadata of all secrets belonging to a tenant (without decrypted values)."""
        with _connection() as conn:
            rows = conn.execute(
                "SELECT id, organization_id, secret_name, metadata, created_at, updated_at FROM tenant_secrets WHERE organization_id = ? ORDER BY secret_name",
                (organization_id,),
            ).fetchall()
        
        results = []
        for row in rows:
            results.append({
                "id": row["id"],
                "organization_id": row["organization_id"],
                "secret_name": row["secret_name"],
                "metadata": json.loads(row["metadata"] or "{}"),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })
        return results

    def delete_secret(self, organization_id: str, secret_name: str) -> bool:
        """Delete a secret for a tenant. Returns True if deleted, False if not found."""
        with _connection() as conn:
            cursor = conn.execute(
                "DELETE FROM tenant_secrets WHERE organization_id = ? AND secret_name = ?",
                (organization_id, secret_name),
            )
            return cursor.rowcount > 0

    @staticmethod
    def redact_string(text: str, secrets: list[str]) -> str:
        """Redact known secret values from logs, reports, or messages."""
        redacted = text
        for s in secrets:
            if s and len(s) >= 4:
                redacted = redacted.replace(s, "[REDACTED_SECRET]")
        return redacted


# Global instance
secret_manager = SecretManager()
