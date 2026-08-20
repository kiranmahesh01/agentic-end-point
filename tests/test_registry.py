"""Tests for the registry service."""

import pytest
from fastapi.testclient import TestClient


class TestRegistry:
    """Tests for registry service."""

    def test_health_check(self, registry_client: TestClient):
        """Test health endpoint."""
        response = registry_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_get_seeded_demo_coder(self, registry_client: TestClient):
        """Test that demo-coder is seeded and retrievable."""
        response = registry_client.get("/v1/components/agent:demo-coder")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["component"]["id"] == "agent:demo-coder"
        assert data["component"]["type"] == "agent"
        assert data["component"]["lifecycle"] == "active"
        assert data["component"]["approval_status"] == "approved"
        assert data["component"]["risk_tier"] == 1

    def test_get_seeded_finance_skill(self, registry_client: TestClient):
        """Test that finance skill is seeded."""
        response = registry_client.get("/v1/components/skill:finance-report:1.4.2")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["component"]["type"] == "skill"

    def test_unknown_component_not_found(self, registry_client: TestClient):
        """Test that unknown components return 404."""
        response = registry_client.get("/v1/components/agent:unknown")
        assert response.status_code == 404

    def test_verify_known_component(self, registry_client: TestClient):
        """Test verification of a known component."""
        response = registry_client.get(
            "/v1/verify/agent:demo-coder",
            params={"definition_hash": "sha256:demo-coder-definition-hash-def456"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["known"] is True
        assert data["active"] is True
        assert data["approved"] is True
        assert data["hash_match"] is True

    def test_verify_unknown_component(self, registry_client: TestClient):
        """Test verification of an unknown component."""
        response = registry_client.get("/v1/verify/agent:unknown")
        assert response.status_code == 200

        data = response.json()
        assert data["known"] is False
        assert data["active"] is False

    def test_suspend_component(self, registry_client: TestClient):
        """Test suspending a component."""
        response = registry_client.post(
            "/v1/components/agent:demo-coder/suspend",
            params={"reason": "Test suspension"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["component"]["lifecycle"] == "suspended"

        verify = registry_client.get("/v1/verify/agent:demo-coder")
        assert verify.json()["active"] is False

    def test_list_components(self, registry_client: TestClient):
        """Test listing components."""
        response = registry_client.get("/v1/components")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert len(data["components"]) >= 2

    def test_register_new_component(self, registry_client: TestClient):
        """Test registering a new component."""
        new_component = {
            "id": "agent:new-agent",
            "type": "agent",
            "owner": "test-user",
            "purpose": "Test agent",
            "publisher": "test",
            "version": "1.0.0",
            "content_hash": "sha256:test-hash",
            "definition_hash": "sha256:test-def-hash",
        }

        response = registry_client.post("/v1/components", json=new_component)
        assert response.status_code == 201

        data = response.json()
        assert data["component"]["lifecycle"] == "proposed"
        assert data["component"]["approval_status"] == "pending"
