"""Integration tests that verify the required test scenarios."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from packages.common.models import ActionResponse, Decision
from packages.common.jwt_utils import create_token, verify_token, revoke_token, clear_revocation_list


class TestRequiredScenarios:
    """
    Tests for the required scenarios specified in the MVP:

    1. Unknown agent denied
    2. Path traversal denied
    3. Raw shell denied
    4. Write outside root denied
    5. Untrusted + exec denied
    6. Missing fields fail closed
    7. Token exp 300s and revoke works
    8. Kill switch revokes and subsequent action denied
    9. Read on approved root allowed for seeded demo-coder
    """

    def test_unknown_agent_denied(self, pdp_client: TestClient, valid_action_request):
        """Test: Unknown agent denied."""
        with patch("services.pdp.app.verify_component") as mock_verify:
            mock_verify.return_value = (False, {}, "Unknown component: agent:unknown")

            request = valid_action_request.copy()
            request["agent_identity"] = "agent:unknown"

            response = pdp_client.post("/v1/decide", json=request)
            assert response.status_code == 200

            data = response.json()
            assert data["decision"] == "DENY"
            assert "unknown" in data["reason"].lower()

    def test_path_traversal_denied(self, broker_client: TestClient):
        """Test: Path traversal denied."""
        request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance": "instance-123",
            "agent_version": "1.0.0",
            "endpoint_id": "endpoint-001",
            "task_id": "task-123",
            "declared_goal": "Test traversal",
            "tool_id": "test-tool",
            "tool_version": "1.0.0",
            "tool_definition_hash": "sha256:test-hash",
            "path": "/approved/workspace/../../../etc/passwd",
            "content": "malicious",
            "input_trust": "trusted",
        }

        response = broker_client.post("/v1/write_file", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "traversal" in data["reason"].lower()

    def test_raw_shell_denied(self, pdp_client: TestClient, valid_action_request):
        """Test: Raw shell denied."""
        with patch("services.pdp.app.verify_component") as mock_verify:
            mock_verify.return_value = (True, {"permissions": {"shell": True}}, "OK")

            request = valid_action_request.copy()
            request["requested_operation"] = "run_command"
            request["arguments"] = {"raw_shell": "rm -rf /"}

            response = pdp_client.post("/v1/decide", json=request)
            assert response.status_code == 200

            data = response.json()
            assert data["decision"] == "DENY"
            assert "raw shell" in data["reason"].lower()

    def test_write_outside_root_denied(self, pdp_client: TestClient, valid_action_request):
        """Test: Write outside root denied."""
        with patch("services.pdp.app.verify_component") as mock_verify:
            mock_verify.return_value = (
                True,
                {"permissions": {"files_write": ["/approved/output"]}},
                "OK",
            )

            request = valid_action_request.copy()
            request["requested_operation"] = "write_file"
            request["target_resource"] = "/unauthorized/location/file.txt"

            response = pdp_client.post("/v1/decide", json=request)
            assert response.status_code == 200

            data = response.json()
            assert data["decision"] == "DENY"

    def test_untrusted_exec_denied(self, pdp_client: TestClient, valid_action_request):
        """Test: Untrusted + exec denied."""
        with patch("services.pdp.app.verify_component") as mock_verify:
            mock_verify.return_value = (True, {"permissions": {"shell": True}}, "OK")

            request = valid_action_request.copy()
            request["requested_operation"] = "run_command"
            request["input_trust"] = "untrusted"
            request["arguments"] = {"command_id": "some_command"}

            response = pdp_client.post("/v1/decide", json=request)
            assert response.status_code == 200

            data = response.json()
            assert data["decision"] == "DENY"
            assert "untrusted" in data["reason"].lower()

    def test_missing_fields_fail_closed(self, pdp_client: TestClient, valid_action_request):
        """Test: Missing fields fail closed."""
        request = valid_action_request.copy()
        request["tool_id"] = ""

        response = pdp_client.post("/v1/decide", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "missing" in data["reason"].lower()

    def test_token_expiry_300s_and_revoke_works(self, identity_client: TestClient):
        """Test: Token exp 300s and revoke works."""
        clear_revocation_list()

        token, claims = create_token(
            user="test-user",
            agent_identity="agent:demo-coder",
            agent_instance_id="instance-123",
            task_id="task-456",
            intent="Test intent",
            device_id="device-001",
        )

        assert claims["exp"] - claims["iat"] == 300

        verified_claims = verify_token(token)
        assert verified_claims["sub"] == "test-user"

        revoke_token(claims["jti"])

        with pytest.raises(Exception) as exc_info:
            verify_token(token)
        assert "revoked" in str(exc_info.value).lower()

    def test_kill_switch_revokes_and_subsequent_denied(
        self, broker_client: TestClient, killswitch_client: TestClient
    ):
        """Test: Kill switch revokes and subsequent action denied."""
        task_id = "task-kill-test"

        broker_client.post("/v1/terminate-task", params={"task_id": task_id})

        request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_instance": "instance-123",
            "agent_version": "1.0.0",
            "endpoint_id": "endpoint-001",
            "task_id": task_id,
            "declared_goal": "Test after kill",
            "tool_id": "test-tool",
            "tool_version": "1.0.0",
            "tool_definition_hash": "sha256:test-hash",
            "path": "/approved/workspace/test.txt",
            "input_trust": "trusted",
        }

        response = broker_client.post("/v1/read_file", json=request)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "DENY"
        assert "terminated" in data["reason"].lower()

    def test_read_approved_root_allowed_for_demo_coder(
        self, broker_client: TestClient, registry_client: TestClient
    ):
        """Test: Read on approved root allowed for seeded demo-coder."""
        verify_response = registry_client.get("/v1/verify/agent:demo-coder")
        assert verify_response.json()["known"] is True
        assert verify_response.json()["active"] is True

        with patch("services.broker.app._consult_pdp") as mock_pdp:
            mock_pdp.return_value = ActionResponse(
                decision=Decision.ALLOW,
                reason="All policy checks passed",
                request_id="test-123",
            )

            request = {
                "user": "demo-user",
                "agent_identity": "agent:demo-coder",
                "agent_instance": "instance-123",
                "agent_version": "1.0.0",
                "endpoint_id": "endpoint-001",
                "task_id": "task-demo",
                "declared_goal": "Read workspace file",
                "tool_id": "file-reader",
                "tool_version": "1.0.0",
                "tool_definition_hash": "sha256:demo-coder-definition-hash-def456",
                "path": "/approved/workspace/data.txt",
                "input_trust": "trusted",
            }

            response = broker_client.post("/v1/read_file", json=request)
            assert response.status_code == 200

            data = response.json()
            assert data["decision"] == "ALLOW"
            assert data["success"] is True


class TestPathSafety:
    """Tests for path safety utilities."""

    def test_canonicalize_removes_traversal(self):
        """Test that path canonicalization removes traversal."""
        from packages.common.path_safety import canonicalize_path

        result = canonicalize_path("/approved/workspace/../../../etc/passwd")
        assert ".." not in result

    def test_is_path_safe_detects_traversal(self):
        """Test that is_path_safe detects traversal."""
        from packages.common.path_safety import is_path_safe

        safe, reason = is_path_safe("/approved/workspace/../etc/passwd")
        assert safe is False
        assert "traversal" in reason.lower()

    def test_is_within_roots(self):
        """Test is_within_roots functionality."""
        from packages.common.path_safety import is_within_roots

        within, _ = is_within_roots("/approved/workspace/file.txt", ["/approved/workspace"])
        assert within is True

        within, _ = is_within_roots("/etc/passwd", ["/approved/workspace"])
        assert within is False


class TestJWTUtils:
    """Tests for JWT utilities."""

    def test_token_contains_required_claims(self):
        """Test that tokens contain all required claims."""
        clear_revocation_list()

        token, claims = create_token(
            user="test-user",
            agent_identity="agent:test",
            agent_instance_id="inst-123",
            task_id="task-456",
            intent="Test intent",
            device_id="device-001",
            tool_id="tool-1",
            tool_version="1.0.0",
            resource="/test/resource",
        )

        assert claims["iss"] == "agentic-endpoint-security"
        assert claims["sub"] == "test-user"
        assert claims["act"]["sub"] == "agent:test"
        assert "jti" in claims
        assert "iat" in claims
        assert "exp" in claims
        assert claims["device_id"] == "device-001"
        assert claims["agent_instance_id"] == "inst-123"
        assert claims["task_id"] == "task-456"
        assert "intent_hash" in claims

    def test_no_pat_passthrough(self):
        """Test that tokens don't pass through raw credentials."""
        token, claims = create_token(
            user="test-user",
            agent_identity="agent:test",
            agent_instance_id="inst-123",
            task_id="task-456",
            intent="Test",
            device_id="device-001",
        )

        assert "password" not in str(claims).lower()
        assert "api_key" not in str(claims).lower()
        assert "secret" not in str(claims).lower()
