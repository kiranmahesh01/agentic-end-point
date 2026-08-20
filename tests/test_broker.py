"""Tests for the broker service."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from packages.common.models import ActionResponse, Decision


def make_read_request(**overrides):
    """Create a read file request with defaults."""
    base = {
        "user": "test-user",
        "agent_identity": "agent:demo-coder",
        "agent_instance": "instance-123",
        "agent_version": "1.0.0",
        "endpoint_id": "endpoint-001",
        "task_id": "task-123",
        "declared_goal": "Test read",
        "tool_id": "test-tool",
        "tool_version": "1.0.0",
        "tool_definition_hash": "sha256:test-hash",
        "path": "/approved/workspace/test.txt",
        "input_trust": "trusted",
    }
    base.update(overrides)
    return base


def make_write_request(**overrides):
    """Create a write file request with defaults."""
    base = make_read_request()
    base.update({
        "path": "/approved/output/test.txt",
        "content": "test content",
    })
    base.update(overrides)
    return base


def make_command_request(**overrides):
    """Create a run command request with defaults."""
    base = make_read_request()
    base.update({
        "command_id": "safe_command",
        "args": {},
    })
    del base["path"]
    base.update(overrides)
    return base


class TestBroker:
    """Tests for broker service."""

    def test_health_check(self, broker_client: TestClient):
        """Test health endpoint."""
        response = broker_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_path_traversal_denied(self, broker_client: TestClient):
        """Test that path traversal is denied at the broker level."""
        request = make_read_request(path="/approved/workspace/../../../etc/passwd")

        response = broker_client.post("/v1/read_file", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert data["success"] is False
        assert "traversal" in data["reason"].lower()

    def test_terminated_task_denied(self, broker_client: TestClient):
        """Test that terminated tasks are denied."""
        broker_client.post("/v1/terminate-task", params={"task_id": "task-terminated"})

        request = make_read_request(task_id="task-terminated")

        response = broker_client.post("/v1/read_file", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "terminated" in data["reason"].lower()

    @patch("services.broker.app._consult_pdp")
    def test_allowed_read(self, mock_pdp, broker_client: TestClient):
        """Test allowed read operation."""
        mock_pdp.return_value = ActionResponse(
            decision=Decision.ALLOW,
            reason="All checks passed",
            request_id="test-123",
        )

        request = make_read_request()

        response = broker_client.post("/v1/read_file", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "ALLOW"
        assert data["success"] is True

    @patch("services.broker.app._consult_pdp")
    def test_denied_write(self, mock_pdp, broker_client: TestClient):
        """Test denied write operation."""
        mock_pdp.return_value = ActionResponse(
            decision=Decision.DENY,
            reason="Write not allowed",
            request_id="test-123",
        )

        request = make_write_request()

        response = broker_client.post("/v1/write_file", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert data["success"] is False

    @patch("services.broker.app._consult_pdp")
    def test_write_requires_approval(self, mock_pdp, broker_client: TestClient):
        """Test write that requires approval."""
        mock_pdp.return_value = ActionResponse(
            decision=Decision.REQUIRE_APPROVAL,
            reason="Untrusted input requires approval",
            request_id="test-123",
            approval_id="apr-test",
        )

        request = make_write_request(input_trust="untrusted")

        response = broker_client.post("/v1/write_file", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "REQUIRE_APPROVAL"
        assert data["approval_id"] is not None

    def test_run_command_without_command_id_denied(self, broker_client: TestClient):
        """Test that commands without command_id are denied."""
        request = make_command_request(command_id="")

        response = broker_client.post("/v1/run_command", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "command_id" in data["reason"].lower()

    @patch("services.broker.app._consult_pdp")
    def test_http_request(self, mock_pdp, broker_client: TestClient):
        """Test HTTP request through broker."""
        mock_pdp.return_value = ActionResponse(
            decision=Decision.ALLOW,
            reason="Egress allowed",
            request_id="test-123",
        )

        request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance": "instance-123",
            "agent_version": "1.0.0",
            "endpoint_id": "endpoint-001",
            "task_id": "task-123",
            "declared_goal": "Fetch report",
            "tool_id": "test-tool",
            "tool_version": "1.0.0",
            "tool_definition_hash": "sha256:test-hash",
            "service_id": "reports",
            "method": "GET",
            "path": "/reports/latest",
            "destination": "reports.internal.example",
            "input_trust": "trusted",
        }

        response = broker_client.post("/v1/http_request", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "ALLOW"

    def test_terminate_task(self, broker_client: TestClient):
        """Test terminating a task."""
        response = broker_client.post(
            "/v1/terminate-task",
            params={"task_id": "task-to-terminate"},
        )
        assert response.status_code == 200
        assert response.json()["success"] is True

        list_response = broker_client.get("/v1/terminated-tasks")
        assert "task-to-terminate" in list_response.json()["terminated_tasks"]
