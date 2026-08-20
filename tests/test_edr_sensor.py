"""Tests for the EDR sensor service."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from services.edr_sensor.app import app, _isolation_log, _isolated_containers


@pytest.fixture
def client():
    """Create test client for EDR sensor service."""
    _isolation_log.clear()
    _isolated_containers.clear()
    return TestClient(app)


class TestEDRSensorHealth:
    """Health check tests."""

    def test_health_check(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "edr-sensor"
        assert "docker" in data


class TestContainerIsolation:
    """Container isolation tests."""

    def test_isolate_without_docker(self, client):
        """Test isolation when Docker is not available."""
        with patch("services.edr_sensor.app._docker_client", None):
            response = client.post(
                "/v1/isolate",
                params={
                    "agent_id": "agent:demo-coder",
                    "container_name": "demo-agent",
                    "reason": "Test isolation"
                }
            )
            assert response.status_code == 200
            data = response.json()
            assert data["simulated"] is True

    def test_isolate_logs_action(self, client):
        """Test that isolation logs the action."""
        with patch("services.edr_sensor.app._docker_client", None):
            client.post(
                "/v1/isolate",
                params={
                    "agent_id": "agent:test",
                    "container_name": "test-container",
                    "reason": "Test"
                }
            )
        
        response = client.get("/v1/log")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] > 0


class TestContainerTermination:
    """Container termination tests."""

    def test_terminate_without_docker(self, client):
        """Test termination when Docker is not available."""
        with patch("services.edr_sensor.app._docker_client", None):
            response = client.post(
                "/v1/terminate",
                params={
                    "agent_id": "agent:demo-coder",
                    "reason": "Kill switch"
                }
            )
            assert response.status_code == 200
            data = response.json()
            assert data["simulated"] is True


class TestContainerRestore:
    """Container restoration tests."""

    def test_restore_without_docker(self, client):
        """Test restoration when Docker is not available."""
        with patch("services.edr_sensor.app._docker_client", None):
            response = client.post(
                "/v1/restore",
                params={"agent_id": "agent:demo-coder"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False


class TestContainerStatus:
    """Container status tests."""

    def test_status_without_docker(self, client):
        """Test status when Docker is not available."""
        with patch("services.edr_sensor.app._docker_client", None):
            response = client.get(
                "/v1/status",
                params={"container_name": "demo-agent"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["docker_available"] is False


class TestIsolatedContainersList:
    """Isolated containers list tests."""

    def test_list_isolated_empty(self, client):
        """Test listing isolated containers when none isolated."""
        response = client.get("/v1/isolated")
        assert response.status_code == 200
        data = response.json()
        assert "isolated_containers" in data


class TestContainersList:
    """Containers list tests."""

    def test_list_containers_without_docker(self, client):
        """Test listing containers when Docker is not available."""
        with patch("services.edr_sensor.app._docker_client", None):
            response = client.get("/v1/containers")
            assert response.status_code == 200
            data = response.json()
            assert data["docker_available"] is False


class TestIsolationWithMockDocker:
    """Tests with mocked Docker client."""

    def test_isolate_with_mock_docker(self, client):
        """Test isolation with mocked Docker client."""
        mock_container = MagicMock()
        mock_container.name = "demo-agent"
        mock_container.status = "running"
        mock_container.attrs = {"NetworkSettings": {"Networks": {"agentic-net": {}}}}
        
        mock_network = MagicMock()
        
        mock_docker = MagicMock()
        mock_docker.containers.list.return_value = [mock_container]
        mock_docker.networks.get.return_value = mock_network
        
        with patch("services.edr_sensor.app._docker_client", mock_docker):
            response = client.post(
                "/v1/isolate",
                params={
                    "agent_id": "agent:demo-coder",
                    "container_name": "demo-agent",
                    "reason": "Test"
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert len(data["actions_taken"]) > 0
