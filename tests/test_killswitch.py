"""Tests for the kill switch service."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock


class TestKillSwitch:
    """Tests for kill switch service."""

    def test_health_check(self, killswitch_client: TestClient):
        """Test health endpoint."""
        response = killswitch_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    @patch("services.killswitch.app._suspend_in_registry")
    @patch("services.killswitch.app._revoke_tokens")
    @patch("services.killswitch.app._terminate_tasks")
    @patch("services.killswitch.app._log_edr_isolate")
    @patch("services.killswitch.app._log_egress_deny")
    @patch("services.killswitch.app._emit_kill_telemetry")
    def test_kill_switch_activation(
        self,
        mock_telemetry,
        mock_egress,
        mock_edr,
        mock_terminate,
        mock_revoke,
        mock_suspend,
        killswitch_client: TestClient,
    ):
        """Test activating the kill switch."""
        mock_suspend.return_value = (True, "Suspended")
        mock_revoke.return_value = (True, 5, "Tokens revoked")
        mock_terminate.return_value = (["task-1", "task-2"], [])
        mock_edr.return_value = True
        mock_egress.return_value = True
        mock_telemetry.return_value = None

        response = killswitch_client.post(
            "/v1/kill",
            json={
                "agent_id": "agent:demo-coder",
                "task_ids": ["task-1", "task-2"],
                "reason": "Test kill switch",
                "initiated_by": "test-admin",
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "completed"
        assert data["registry_suspended"] is True
        assert data["tokens_revoked"] == 5
        assert data["tasks_terminated"] == ["task-1", "task-2"]
        assert data["edr_isolate_logged"] is True
        assert data["egress_deny_logged"] is True
        assert len(data["errors"]) == 0

    @patch("services.killswitch.app._suspend_in_registry")
    @patch("services.killswitch.app._revoke_tokens")
    @patch("services.killswitch.app._terminate_tasks")
    @patch("services.killswitch.app._log_edr_isolate")
    @patch("services.killswitch.app._log_egress_deny")
    @patch("services.killswitch.app._emit_kill_telemetry")
    def test_kill_switch_with_errors(
        self,
        mock_telemetry,
        mock_egress,
        mock_edr,
        mock_terminate,
        mock_revoke,
        mock_suspend,
        killswitch_client: TestClient,
    ):
        """Test kill switch with partial failures."""
        mock_suspend.return_value = (False, "Registry timeout")
        mock_revoke.return_value = (True, 3, "OK")
        mock_terminate.return_value = ([], ["Failed to terminate task-1"])
        mock_edr.return_value = True
        mock_egress.return_value = True
        mock_telemetry.return_value = None

        response = killswitch_client.post(
            "/v1/kill",
            json={
                "agent_id": "agent:demo-coder",
                "task_ids": ["task-1"],
                "reason": "Test with errors",
                "initiated_by": "test-admin",
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "completed_with_errors"
        assert len(data["errors"]) > 0

    @patch("services.killswitch.app._suspend_in_registry")
    @patch("services.killswitch.app._revoke_tokens")
    @patch("services.killswitch.app._terminate_tasks")
    @patch("services.killswitch.app._log_edr_isolate")
    @patch("services.killswitch.app._log_egress_deny")
    @patch("services.killswitch.app._emit_kill_telemetry")
    def test_get_kill_status(
        self,
        mock_telemetry,
        mock_egress,
        mock_edr,
        mock_terminate,
        mock_revoke,
        mock_suspend,
        killswitch_client: TestClient,
    ):
        """Test getting kill switch status."""
        mock_suspend.return_value = (True, "OK")
        mock_revoke.return_value = (True, 1, "OK")
        mock_terminate.return_value = ([], [])
        mock_edr.return_value = True
        mock_egress.return_value = True
        mock_telemetry.return_value = None

        kill_response = killswitch_client.post(
            "/v1/kill",
            json={
                "agent_id": "agent:demo-coder",
                "task_ids": [],
                "reason": "Test",
                "initiated_by": "admin",
            },
        )
        kill_id = kill_response.json()["kill_id"]

        status_response = killswitch_client.get(f"/v1/status/{kill_id}")
        assert status_response.status_code == 200
        assert status_response.json()["kill_id"] == kill_id

    @patch("services.killswitch.app._suspend_in_registry")
    @patch("services.killswitch.app._revoke_tokens")
    @patch("services.killswitch.app._terminate_tasks")
    @patch("services.killswitch.app._log_edr_isolate")
    @patch("services.killswitch.app._log_egress_deny")
    @patch("services.killswitch.app._emit_kill_telemetry")
    def test_list_kill_history(
        self,
        mock_telemetry,
        mock_egress,
        mock_edr,
        mock_terminate,
        mock_revoke,
        mock_suspend,
        killswitch_client: TestClient,
    ):
        """Test listing kill switch history."""
        mock_suspend.return_value = (True, "OK")
        mock_revoke.return_value = (True, 0, "OK")
        mock_terminate.return_value = ([], [])
        mock_edr.return_value = True
        mock_egress.return_value = True
        mock_telemetry.return_value = None

        for i in range(3):
            killswitch_client.post(
                "/v1/kill",
                json={
                    "agent_id": f"agent:test-{i}",
                    "task_ids": [],
                    "reason": f"Test {i}",
                    "initiated_by": "admin",
                },
            )

        response = killswitch_client.get("/v1/status")
        assert response.status_code == 200
        assert response.json()["count"] == 3

    def test_kill_status_not_found(self, killswitch_client: TestClient):
        """Test getting non-existent kill status."""
        response = killswitch_client.get("/v1/status/nonexistent")
        assert response.status_code == 404
