"""Tests for the Policy Decision Point service."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock


class TestPDP:
    """Tests for PDP service."""

    def test_health_check(self, pdp_client: TestClient):
        """Test health endpoint."""
        response = pdp_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_missing_required_fields_denied(self, pdp_client: TestClient):
        """Test that missing required fields result in DENY."""
        incomplete_request = {
            "user": "test-user",
        }

        response = pdp_client.post("/v1/decide", json=incomplete_request)
        assert response.status_code == 422

    def test_missing_agent_identity_denied(self, pdp_client: TestClient, valid_action_request):
        """Test that missing agent_identity results in DENY."""
        request = valid_action_request.copy()
        request["agent_identity"] = ""

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "Missing required field" in data["reason"]

    @patch("services.pdp.app.verify_component")
    def test_unknown_agent_denied(self, mock_verify, pdp_client: TestClient, valid_action_request):
        """Test that unknown agents are denied."""
        mock_verify.return_value = (False, {}, "Unknown component: agent:unknown")

        request = valid_action_request.copy()
        request["agent_identity"] = "agent:unknown"

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"

    @patch("services.pdp.app.verify_component")
    def test_path_traversal_denied(self, mock_verify, pdp_client: TestClient, valid_action_request):
        """Test that path traversal attempts are denied."""
        mock_verify.return_value = (
            True,
            {"permissions": {"files_read": ["/approved/workspace"]}},
            "OK",
        )

        request = valid_action_request.copy()
        request["target_resource"] = "/approved/workspace/../../../etc/passwd"

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "traversal" in data["reason"].lower()

    @patch("services.pdp.app.verify_component")
    def test_raw_shell_denied(self, mock_verify, pdp_client: TestClient, valid_action_request):
        """Test that raw shell commands are denied."""
        mock_verify.return_value = (
            True,
            {"permissions": {"shell": True}},
            "OK",
        )

        request = valid_action_request.copy()
        request["requested_operation"] = "run_command"
        request["target_resource"] = "ls -la"
        request["arguments"] = {"raw_shell": "rm -rf /"}

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "raw shell" in data["reason"].lower()

    @patch("services.pdp.app.verify_component")
    def test_write_outside_root_denied(self, mock_verify, pdp_client: TestClient, valid_action_request):
        """Test that writes outside approved roots are denied."""
        mock_verify.return_value = (
            True,
            {"permissions": {"files_write": ["/approved/output"]}},
            "OK",
        )

        request = valid_action_request.copy()
        request["requested_operation"] = "write_file"
        request["target_resource"] = "/tmp/unauthorized/file.txt"

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"

    @patch("services.pdp.app.verify_component")
    def test_untrusted_input_exec_denied(self, mock_verify, pdp_client: TestClient, valid_action_request):
        """Test that untrusted input + exec is denied."""
        mock_verify.return_value = (
            True,
            {"permissions": {"shell": True}},
            "OK",
        )

        request = valid_action_request.copy()
        request["requested_operation"] = "run_command"
        request["input_trust"] = "untrusted"
        request["arguments"] = {"command_id": "safe_command"}

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "untrusted" in data["reason"].lower()

    @patch("services.pdp.app.verify_component")
    def test_untrusted_input_write_requires_approval(
        self, mock_verify, pdp_client: TestClient, valid_action_request
    ):
        """Test that untrusted input + write requires approval."""
        mock_verify.return_value = (
            True,
            {"permissions": {"files_write": ["/approved/output"]}},
            "OK",
        )

        request = valid_action_request.copy()
        request["requested_operation"] = "write_file"
        request["target_resource"] = "/approved/output/test.txt"
        request["input_trust"] = "untrusted"

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "REQUIRE_APPROVAL"

    @patch("services.pdp.app.verify_component")
    def test_valid_read_allowed(self, mock_verify, pdp_client: TestClient, valid_action_request):
        """Test that valid reads are allowed."""
        mock_verify.return_value = (
            True,
            {
                "permissions": {"files_read": ["/approved/workspace"]},
                "lifecycle": "active",
            },
            "OK",
        )

        response = pdp_client.post("/v1/decide", json=valid_action_request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "ALLOW"

    def test_get_policy(self, pdp_client: TestClient):
        """Test getting policy configuration."""
        response = pdp_client.get("/v1/policy")
        assert response.status_code == 200

        data = response.json()
        assert "version" in data
        assert "required_fields" in data
        assert data["default_decision"] == "DENY"
