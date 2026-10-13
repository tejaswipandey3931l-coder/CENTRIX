"""Tests for tenant-isolated encrypted secret management."""
import pytest
from agent.secrets import SecretManager


def test_secret_encryption_and_decryption(tmp_path, monkeypatch):
    db_file = tmp_path / "test_secrets.db"
    monkeypatch.setenv("CENTRIX_DB_PATH", str(db_file))
    
    mgr = SecretManager(master_key="super-secret-master-key-xyz-123")
    org_a = "tenant-alpha"
    
    secret_id = mgr.set_secret(
        organization_id=org_a,
        secret_name="XKIRO_API_KEY",
        plaintext_value="xkiro_live_key_99999_secret_token",
        metadata={"provider": "xkiro", "tier": "free"},
    )
    assert secret_id.startswith("sec-")

    # Decrypt
    val = mgr.get_secret(org_a, "XKIRO_API_KEY")
    assert val == "xkiro_live_key_99999_secret_token"


def test_tenant_isolation(tmp_path, monkeypatch):
    db_file = tmp_path / "test_secrets.db"
    monkeypatch.setenv("CENTRIX_DB_PATH", str(db_file))
    
    mgr = SecretManager(master_key="super-secret-master-key-xyz-123")
    org_a = "tenant-alpha"
    org_b = "tenant-beta"

    mgr.set_secret(org_a, "API_KEY", "key-for-alpha")
    mgr.set_secret(org_b, "API_KEY", "key-for-beta")

    assert mgr.get_secret(org_a, "API_KEY") == "key-for-alpha"
    assert mgr.get_secret(org_b, "API_KEY") == "key-for-beta"

    # Alpha cannot see Beta's secret if names differ
    mgr.set_secret(org_b, "PRIVATE_TOKEN", "beta-only-secret")
    assert mgr.get_secret(org_a, "PRIVATE_TOKEN") is None


def test_secret_deletion(tmp_path, monkeypatch):
    db_file = tmp_path / "test_secrets.db"
    monkeypatch.setenv("CENTRIX_DB_PATH", str(db_file))
    
    mgr = SecretManager(master_key="super-secret-master-key-xyz-123")
    org = "tenant-gamma"

    mgr.set_secret(org, "TEMP_TOKEN", "temporary_value")
    assert mgr.get_secret(org, "TEMP_TOKEN") == "temporary_value"

    deleted = mgr.delete_secret(org, "TEMP_TOKEN")
    assert deleted is True
    assert mgr.get_secret(org, "TEMP_TOKEN") is None
    assert mgr.delete_secret(org, "TEMP_TOKEN") is False


def test_secret_redaction():
    text = "Error occurred connecting to https://api.xkiro.com with key xkiro_live_secret_key_12345"
    redacted = SecretManager.redact_string(text, ["xkiro_live_secret_key_12345"])
    assert "xkiro_live_secret_key_12345" not in redacted
    assert "[REDACTED_SECRET]" in redacted
