"""Tests for the isolated desktop service (computer-use sandbox)."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from services.isolated_desktop.app import app, _action_log


@pytest.fixture
def client():
    """Create test client for isolated desktop service."""
    _action_log.clear()
    return TestClient(app)


class TestIsolatedDesktopHealth:
    """Health check tests."""

    def test_health_check(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "isolated-desktop"
        assert "xvfb_running" in data
        assert "note" in data
        assert "operator" in data["note"].lower() or "isolated" in data["note"].lower()


class TestTemplatesList:
    """Template listing tests."""

    def test_list_templates(self, client):
        """Test listing available templates."""
        response = client.get("/v1/templates")
        assert response.status_code == 200
        data = response.json()
        assert "templates" in data
        assert "note" in data
        assert "click_button" in data["templates"]
        assert "type_text" in data["templates"]
        assert "submit_form" in data["templates"]

    def test_templates_have_approval_info(self, client):
        """Test that templates include approval requirements."""
        response = client.get("/v1/templates")
        templates = response.json()["templates"]
        
        for name, info in templates.items():
            assert "requires_approval" in info
            assert "high_impact" in info
            assert "description" in info


class TestUIActionExecution:
    """UI action execution tests."""

    def test_unknown_template_rejected(self, client):
        """Test that unknown template is rejected."""
        response = client.post("/v1/execute", json={
            "template_id": "unknown_action",
            "target_descriptor": "some_button",
        })
        assert response.status_code == 400
        assert "unknown template" in response.json()["detail"].lower()

    def test_click_button_simulated(self, client):
        """Test click button action (simulated without Xvfb)."""
        with patch("services.isolated_desktop.app._init_xvfb", return_value=False):
            response = client.post("/v1/execute", json={
                "template_id": "click_button",
                "target_descriptor": "Submit",
            })
            assert response.status_code == 200
            data = response.json()
            assert "action_id" in data
            assert "Xvfb" in data.get("error", "")

    def test_type_text_simulated(self, client):
        """Test type text action (simulated without Xvfb)."""
        with patch("services.isolated_desktop.app._init_xvfb", return_value=False):
            response = client.post("/v1/execute", json={
                "template_id": "type_text",
                "target_descriptor": "username_field",
                "parameters": {"text": "test_user"},
            })
            assert response.status_code == 200

    def test_take_screenshot_simulated(self, client):
        """Test screenshot action (simulated without Xvfb)."""
        with patch("services.isolated_desktop.app._init_xvfb", return_value=False):
            response = client.post("/v1/execute", json={
                "template_id": "take_screenshot",
                "target_descriptor": "screen",
            })
            assert response.status_code == 200


class TestHighImpactTemplates:
    """High-impact template tests."""

    def test_submit_form_requires_approval(self, client):
        """Test that submit_form requires approval."""
        response = client.post("/v1/execute", json={
            "template_id": "submit_form",
            "target_descriptor": "login_form",
        })
        assert response.status_code == 403
        assert "approval" in response.json()["detail"].lower()

    def test_close_window_requires_approval(self, client):
        """Test that close_window requires approval."""
        response = client.post("/v1/execute", json={
            "template_id": "close_window",
            "target_descriptor": "main_window",
        })
        assert response.status_code == 403

    def test_download_file_requires_approval(self, client):
        """Test that download_file requires approval."""
        response = client.post("/v1/execute", json={
            "template_id": "download_file",
            "target_descriptor": "download_link",
            "parameters": {"url": "http://example.com/file.pdf"},
        })
        assert response.status_code == 403

    def test_high_impact_with_approval_proceeds(self, client):
        """Test that high-impact with approval_id proceeds."""
        with patch("services.isolated_desktop.app._init_xvfb", return_value=False):
            response = client.post("/v1/execute", json={
                "template_id": "submit_form",
                "target_descriptor": "login_form",
                "parameters": {"approval_id": "apr-valid123"},
            })
            assert response.status_code == 200


class TestActionLog:
    """Action audit log tests."""

    def test_actions_logged(self, client):
        """Test that actions are logged."""
        with patch("services.isolated_desktop.app._init_xvfb", return_value=False):
            client.post("/v1/execute", json={
                "template_id": "click_button",
                "target_descriptor": "test_button",
            })
        
        response = client.get("/v1/log")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] > 0
        
        entry = data["entries"][-1]
        assert entry["template_id"] == "click_button"
        assert entry["target"] == "test_button"
        assert "timestamp" in entry
        assert "action_id" in entry


class TestSandboxStatus:
    """Sandbox status tests."""

    def test_status_shows_isolation(self, client):
        """Test that status shows isolation settings."""
        response = client.get("/v1/status")
        assert response.status_code == 200
        data = response.json()
        
        assert data["host_display_access"] is False
        assert data["dev_input_access"] is False
        assert "safety_note" in data
        assert "operator" in data["safety_note"].lower() or "no access" in data["safety_note"].lower()


class TestNoRawClickKeystream:
    """Tests to ensure raw click/keystream API is not exposed."""

    def test_no_raw_click_endpoint(self, client):
        """Test that there's no raw click endpoint."""
        response = client.post("/v1/raw_click", json={"x": 100, "y": 200})
        assert response.status_code == 404 or response.status_code == 405

    def test_no_raw_keypress_endpoint(self, client):
        """Test that there's no raw keypress endpoint."""
        response = client.post("/v1/raw_keypress", json={"key": "a"})
        assert response.status_code == 404 or response.status_code == 405
