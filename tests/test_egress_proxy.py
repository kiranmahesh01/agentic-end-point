"""Tests for the egress proxy service."""

import pytest
from fastapi.testclient import TestClient

from services.egress_proxy.app import app, _allowlist, _blocked_agents


@pytest.fixture
def client():
    """Create test client for egress proxy service."""
    _allowlist.clear()
    _allowlist.add("reports.internal.example")
    _blocked_agents.clear()
    return TestClient(app)


class TestEgressProxyHealth:
    """Health check tests."""

    def test_health_check(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "egress-proxy"


class TestAllowlistCheck:
    """Allowlist check tests."""

    def test_allowed_destination(self, client):
        """Test that allowlisted destination is allowed."""
        response = client.get(
            "/v1/check",
            params={"destination": "reports.internal.example", "agent_id": "test-agent"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is True

    def test_denied_destination(self, client):
        """Test that non-allowlisted destination is denied."""
        response = client.get(
            "/v1/check",
            params={"destination": "evil.attacker.com", "agent_id": "test-agent"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is False
        assert "not in allowlist" in data["reason"].lower()

    def test_internal_services_always_allowed(self, client):
        """Test that internal services are always allowed."""
        for service in ["registry", "pdp", "broker", "localhost"]:
            response = client.get(
                "/v1/check",
                params={"destination": service, "agent_id": "test-agent"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["allowed"] is True


class TestAgentBlocking:
    """Agent blocking tests (kill switch integration)."""

    def test_block_agent(self, client):
        """Test blocking an agent."""
        response = client.post(
            "/v1/block-agent",
            params={"agent_id": "agent:demo-coder", "reason": "Kill switch"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["blocked"] is True

    def test_blocked_agent_denied_egress(self, client):
        """Test that blocked agent is denied even to allowed destinations."""
        client.post("/v1/block-agent", params={"agent_id": "agent:blocked"})
        
        response = client.get(
            "/v1/check",
            params={"destination": "reports.internal.example", "agent_id": "agent:blocked"}
        )
        data = response.json()
        assert data["allowed"] is False
        assert "blocked" in data["reason"].lower()

    def test_unblock_agent(self, client):
        """Test unblocking an agent."""
        client.post("/v1/block-agent", params={"agent_id": "agent:test"})
        client.post("/v1/unblock-agent", params={"agent_id": "agent:test"})
        
        response = client.get("/v1/blocked-agents")
        data = response.json()
        assert "agent:test" not in data["blocked_agents"]


class TestProxyRequest:
    """Proxy request tests."""

    def test_denied_destination_returns_403(self, client):
        """Test that proxy request to denied destination returns 403."""
        response = client.post("/v1/proxy", json={
            "destination": "evil.attacker.com",
            "method": "GET",
            "path": "/data",
            "agent_id": "agent:demo-coder",
        })
        assert response.status_code == 403
        assert "not in allowlist" in response.json()["detail"].lower()

    def test_blocked_agent_returns_403(self, client):
        """Test that blocked agent returns 403."""
        client.post("/v1/block-agent", params={"agent_id": "agent:blocked"})
        
        response = client.post("/v1/proxy", json={
            "destination": "reports.internal.example",
            "method": "GET",
            "path": "/report",
            "agent_id": "agent:blocked",
        })
        assert response.status_code == 403
        assert "blocked" in response.json()["detail"].lower()


class TestAllowlistManagement:
    """Allowlist management tests."""

    def test_get_allowlist(self, client):
        """Test getting the allowlist."""
        response = client.get("/v1/allowlist")
        assert response.status_code == 200
        data = response.json()
        assert "allowlist" in data
        assert "always_allowed" in data

    def test_add_to_allowlist(self, client):
        """Test adding to the allowlist."""
        response = client.post("/v1/allowlist", params={"destination": "new-service.example"})
        assert response.status_code == 200
        
        check_response = client.get(
            "/v1/check",
            params={"destination": "new-service.example", "agent_id": "test"}
        )
        assert check_response.json()["allowed"] is True

    def test_remove_from_allowlist(self, client):
        """Test removing from the allowlist."""
        client.post("/v1/allowlist", params={"destination": "temp.example"})
        client.delete("/v1/allowlist", params={"destination": "temp.example"})
        
        check_response = client.get(
            "/v1/check",
            params={"destination": "temp.example", "agent_id": "test"}
        )
        assert check_response.json()["allowed"] is False


class TestDenyLog:
    """Deny log tests."""

    def test_deny_log_records_denials(self, client):
        """Test that deny log records blocked requests."""
        client.get(
            "/v1/check",
            params={"destination": "evil.com", "agent_id": "test"}
        )
        
        response = client.get("/v1/deny-log")
        assert response.status_code == 200
