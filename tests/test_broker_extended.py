"""Extended tests for broker - computer-use and offline mode."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock
import httpx

from services.broker.app import app, _terminated_tasks, _local_cache
from packages.common.models import Decision, ActionResponse, InputTrust


@pytest.fixture
def client():
    """Create test client for broker service."""
    _terminated_tasks.clear()
    _local_cache.clear()
    return TestClient(app)


def make_base_request():
    """Create base request data."""
    return {
        "user": "test-user",
        "agent_identity": "agent:demo-coder",
        "agent_instance": "instance-123",
        "agent_version": "1.0.0",
        "endpoint_id": "endpoint-456",
        "task_id": "task-789",
        "declared_goal": "Test goal",
        "tool_id": "tool-001",
        "tool_version": "1.0.0",
        "tool_definition_hash": "sha256:demo-coder-definition-hash-def456",
        "input_source": "user",
        "input_trust": "trusted",
        "data_classification": "internal",
    }


class TestComputerUseAdapter:
    """Computer-use adapter tests."""

    def test_automate_ui_endpoint_exists(self, client):
        """Test that automate_ui endpoint exists."""
        request = make_base_request()
        request["action_template_id"] = "click_button"
        request["target_descriptor"] = "test_button"
        request["parameters"] = {}
        
        response = client.post("/v1/automate_ui", json=request)
        assert response.status_code == 200

    def test_automate_ui_denied_for_non_permitted_agent(self, client):
        """Test that computer-use is denied by default."""
        request = make_base_request()
        request["action_template_id"] = "click_button"
        request["target_descriptor"] = "test_button"
        request["parameters"] = {}
        
        mock_pdp_response = ActionResponse(
            decision=Decision.DENY,
            reason="Computer-use not permitted for this component",
            request_id="test-123",
        )
        
        with patch("services.broker.app._consult_pdp", return_value=mock_pdp_response):
            response = client.post("/v1/automate_ui", json=request)
            assert response.status_code == 200
            data = response.json()
            assert data["decision"] == "DENY"


class TestOfflineMode:
    """Offline mode (Class D) tests."""

    def test_pdp_status_endpoint(self, client):
        """Test PDP status endpoint exists."""
        response = client.get("/v1/pdp-status")
        assert response.status_code == 200
        data = response.json()
        assert "pdp_available" in data
        assert "mode" in data

    def test_write_fails_when_pdp_unreachable(self, client):
        """Test that writes fail closed when PDP is unreachable."""
        request = make_base_request()
        request["path"] = "/approved/output/test.txt"
        request["content"] = "test content"
        
        mock_response = ActionResponse(
            decision=Decision.DENY,
            reason="PDP unreachable - fail closed (Class D offline)",
            request_id="test-123",
        )
        
        with patch("services.broker.app._consult_pdp", return_value=mock_response):
            response = client.post("/v1/write_file", json=request)
            assert response.status_code == 200
            data = response.json()
            assert data["decision"] == "DENY"

    def test_command_fails_when_pdp_unreachable(self, client):
        """Test that commands fail closed when PDP is unreachable."""
        request = make_base_request()
        request["command_id"] = "safe_command"
        request["args"] = {}
        
        mock_response = ActionResponse(
            decision=Decision.DENY,
            reason="PDP timeout - fail closed",
            request_id="test-123",
        )
        
        with patch("services.broker.app._consult_pdp", return_value=mock_response):
            response = client.post("/v1/run_command", json=request)
            assert response.status_code == 200
            data = response.json()
            assert data["decision"] == "DENY"


class TestCacheForClassA:
    """Cache tests for Class A operations."""

    def test_read_uses_cache_after_first_call(self, client):
        """Test that reads use cache for approved roots after first call."""
        request = make_base_request()
        request["path"] = "/approved/workspace/file.txt"
        
        mock_response = ActionResponse(
            decision=Decision.ALLOW,
            reason="Allowed",
            request_id="test-123",
        )
        
        with patch("services.broker.app._consult_pdp", return_value=mock_response) as mock_pdp:
            response1 = client.post("/v1/read_file", json=request)
            assert response1.status_code == 200
            assert response1.json()["decision"] == "ALLOW"
            
            response2 = client.post("/v1/read_file", json=request)
            assert response2.status_code == 200
            assert response2.json()["decision"] == "ALLOW"


class TestTerminatedTaskChecks:
    """Terminated task check tests."""

    def test_terminated_task_denied_for_automate_ui(self, client):
        """Test that terminated tasks are denied for automate_ui."""
        _terminated_tasks.add("task-terminated")
        
        request = make_base_request()
        request["task_id"] = "task-terminated"
        request["action_template_id"] = "click_button"
        request["target_descriptor"] = "button"
        request["parameters"] = {}
        
        response = client.post("/v1/automate_ui", json=request)
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert "terminated" in data["reason"].lower()

    def test_terminated_task_denied_for_write(self, client):
        """Test that terminated tasks are denied for writes."""
        _terminated_tasks.add("task-terminated")
        
        request = make_base_request()
        request["task_id"] = "task-terminated"
        request["path"] = "/approved/output/test.txt"
        request["content"] = "test"
        
        response = client.post("/v1/write_file", json=request)
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "DENY"
        assert "terminated" in data["reason"].lower()
