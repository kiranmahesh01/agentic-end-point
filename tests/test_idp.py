"""Tests for the local IdP service."""

import pytest
from fastapi.testclient import TestClient

from services.idp.app import app, get_public_key, get_key_id


@pytest.fixture
def client():
    """Create test client for IdP service."""
    return TestClient(app)


class TestIdPHealth:
    """Health check tests."""

    def test_health_check(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "idp"


class TestJWKS:
    """JWKS endpoint tests."""

    def test_jwks_endpoint(self, client):
        """Test JWKS endpoint returns valid keys."""
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        data = response.json()
        assert "keys" in data
        assert len(data["keys"]) > 0
        
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert "n" in key
        assert "e" in key
        assert "kid" in key

    def test_openid_configuration(self, client):
        """Test OpenID Connect discovery endpoint."""
        response = client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        data = response.json()
        assert "issuer" in data
        assert "jwks_uri" in data
        assert "token_endpoint" in data


class TestTokenIssuance:
    """Token issuance tests."""

    def test_issue_token(self, client):
        """Test token issuance."""
        response = client.post("/v1/token", json={
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Read files for code review",
            "device_id": "device-789",
            "scope": ["read", "write"],
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 300

    def test_token_has_rs256_signature(self, client):
        """Verify token is RS256 signed."""
        import jwt
        
        response = client.post("/v1/token", json={
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Test intent",
            "device_id": "device-789",
        })
        
        token = response.json()["access_token"]
        
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
        assert "kid" in header

    def test_verify_token(self, client):
        """Test token verification endpoint."""
        issue_response = client.post("/v1/token", json={
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Test",
            "device_id": "device-789",
        })
        token = issue_response.json()["access_token"]
        
        verify_response = client.get(f"/v1/verify?token={token}")
        assert verify_response.status_code == 200
        data = verify_response.json()
        assert data["valid"] is True
        assert "claims" in data


class TestTokenRevocation:
    """Token revocation tests."""

    def test_revoke_token(self, client):
        """Test token revocation."""
        issue_response = client.post("/v1/token", json={
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Test",
            "device_id": "device-789",
        })
        token = issue_response.json()["access_token"]
        
        revoke_response = client.post("/v1/revoke", json={"token": token})
        assert revoke_response.status_code == 200
        assert revoke_response.json()["revoked"] is True

    def test_revoked_token_verification_fails(self, client):
        """Test that revoked token fails verification."""
        issue_response = client.post("/v1/token", json={
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Test",
            "device_id": "device-789",
        })
        token = issue_response.json()["access_token"]
        
        client.post("/v1/revoke", json={"token": token})
        
        verify_response = client.get(f"/v1/verify?token={token}")
        data = verify_response.json()
        assert data["valid"] is False
        assert "revoked" in data.get("error", "").lower()


class TestTokenExchange:
    """RFC 8693 Token Exchange tests."""

    def test_token_exchange(self, client):
        """Test token exchange endpoint."""
        response = client.post("/v1/token-exchange", json={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "mock-user-token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "agentic-endpoint-security",
            "scope": "read write",
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"

    def test_invalid_grant_type_rejected(self, client):
        """Test that invalid grant type is rejected."""
        response = client.post("/v1/token-exchange", json={
            "grant_type": "invalid",
            "subject_token": "mock-token",
        })
        assert response.status_code == 400
