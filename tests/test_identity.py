"""Tests for the identity service."""

import time
import pytest
from fastapi.testclient import TestClient

from packages.common.jwt_utils import verify_token, JWT_EXPIRY_SECONDS


class TestIdentity:
    """Tests for identity service."""

    def test_health_check(self, identity_client: TestClient):
        """Test health endpoint."""
        response = identity_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_issue_token(self, identity_client: TestClient):
        """Test issuing a token."""
        request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Read test file",
            "device_id": "device-001",
        }

        response = identity_client.post("/v1/token", json=request)
        assert response.status_code == 200

        data = response.json()
        assert "token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == JWT_EXPIRY_SECONDS
        assert "jti" in data

    def test_token_expiry_is_300_seconds(self, identity_client: TestClient):
        """Test that token expiry is 300 seconds (5 minutes)."""
        request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Test intent",
            "device_id": "device-001",
        }

        response = identity_client.post("/v1/token", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["expires_in"] == 300

        claims = verify_token(data["token"])
        assert claims["exp"] - claims["iat"] == 300

    def test_verify_valid_token(self, identity_client: TestClient):
        """Test verifying a valid token."""
        token_request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Test intent",
            "device_id": "device-001",
        }

        token_response = identity_client.post("/v1/token", json=token_request)
        token = token_response.json()["token"]

        verify_response = identity_client.get("/v1/verify", params={"token": token})
        assert verify_response.status_code == 200

        data = verify_response.json()
        assert data["valid"] is True
        assert data["claims"]["sub"] == "test-user"
        assert data["claims"]["act"]["sub"] == "agent:demo-coder"

    def test_revoke_token(self, identity_client: TestClient):
        """Test revoking a token."""
        token_request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance_id": "instance-123",
            "task_id": "task-456",
            "intent": "Test intent",
            "device_id": "device-001",
        }

        token_response = identity_client.post("/v1/token", json=token_request)
        token_data = token_response.json()
        token = token_data["token"]
        jti = token_data["jti"]

        revoke_response = identity_client.post(
            "/v1/revoke",
            json={"jti": jti, "reason": "Test revocation"},
        )
        assert revoke_response.status_code == 200
        assert revoke_response.json()["success"] is True

        verify_response = identity_client.get("/v1/verify", params={"token": token})
        assert verify_response.json()["valid"] is False

    def test_revoke_agent_tokens(self, identity_client: TestClient):
        """Test revoking all tokens for an agent."""
        for i in range(3):
            identity_client.post(
                "/v1/token",
                json={
                    "user": "test-user",
                    "agent_identity": "agent:demo-coder",
                    "agent_instance_id": f"instance-{i}",
                    "task_id": f"task-{i}",
                    "intent": "Test intent",
                    "device_id": "device-001",
                },
            )

        response = identity_client.post(
            "/v1/revoke-agent",
            params={
                "agent_identity": "agent:demo-coder",
                "reason": "Kill switch test",
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["tokens_revoked"] == 3

    def test_list_tokens(self, identity_client: TestClient):
        """Test listing tokens."""
        identity_client.post(
            "/v1/token",
            json={
                "user": "test-user",
                "agent_identity": "agent:demo-coder",
                "agent_instance_id": "instance-1",
                "task_id": "task-1",
                "intent": "Test intent",
                "device_id": "device-001",
            },
        )

        response = identity_client.get("/v1/tokens")
        assert response.status_code == 200
        assert response.json()["count"] >= 1
