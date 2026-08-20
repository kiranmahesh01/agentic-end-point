"""Tests for the telemetry service."""

import pytest
from fastapi.testclient import TestClient


class TestTelemetry:
    """Tests for telemetry service."""

    def test_health_check(self, telemetry_client: TestClient):
        """Test health endpoint."""
        response = telemetry_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_create_event(self, telemetry_client: TestClient):
        """Test creating a telemetry event."""
        event = {
            "event_id": "evt-123",
            "trace_id": "trace-456",
            "event_type": "read_file_allowed",
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "operation": "read_file",
            "target": "/approved/workspace/test.txt",
            "decision": "ALLOW",
            "reason": "All checks passed",
            "metadata": {"file_size": 1024},
        }

        response = telemetry_client.post("/v1/events", json=event)
        assert response.status_code == 201

        data = response.json()
        assert data["event_id"] == "evt-123"
        assert data["trace_id"] == "trace-456"
        assert "timestamp" in data

    def test_secrets_are_redacted(self, telemetry_client: TestClient):
        """Test that secrets are redacted from metadata."""
        event = {
            "event_id": "evt-secret",
            "trace_id": "trace-secret",
            "event_type": "test_event",
            "metadata": {
                "api_key": "super-secret-key",
                "password": "hunter2",
                "normal_field": "visible",
            },
        }

        response = telemetry_client.post("/v1/events", json=event)
        assert response.status_code == 201

        data = response.json()
        assert data["metadata"]["api_key"] == "[REDACTED]"
        assert data["metadata"]["password"] == "[REDACTED]"
        assert data["metadata"]["normal_field"] == "visible"

    def test_chain_of_thought_redacted(self, telemetry_client: TestClient):
        """Test that chain of thought is redacted."""
        event = {
            "event_id": "evt-cot",
            "trace_id": "trace-cot",
            "event_type": "test_event",
            "metadata": {
                "chain_of_thought": "Let me think step by step...",
                "reasoning": "I believe this because...",
            },
        }

        response = telemetry_client.post("/v1/events", json=event)
        assert response.status_code == 201

        data = response.json()
        assert data["metadata"]["chain_of_thought"] == "[REDACTED]"
        assert data["metadata"]["reasoning"] == "[REDACTED]"

    def test_get_event_by_id(self, telemetry_client: TestClient):
        """Test getting an event by ID."""
        telemetry_client.post(
            "/v1/events",
            json={
                "event_id": "evt-get-test",
                "trace_id": "trace-get",
                "event_type": "test_event",
            },
        )

        response = telemetry_client.get("/v1/events/evt-get-test")
        assert response.status_code == 200
        assert response.json()["event_id"] == "evt-get-test"

    def test_get_trace(self, telemetry_client: TestClient):
        """Test getting all events for a trace."""
        trace_id = "trace-multi"

        for i in range(3):
            telemetry_client.post(
                "/v1/events",
                json={
                    "event_id": f"evt-trace-{i}",
                    "trace_id": trace_id,
                    "event_type": f"event_{i}",
                },
            )

        response = telemetry_client.get(f"/v1/trace/{trace_id}")
        assert response.status_code == 200

        data = response.json()
        assert data["trace_id"] == trace_id
        assert data["event_count"] == 3

    def test_list_events_with_filter(self, telemetry_client: TestClient):
        """Test listing events with filters."""
        for event_type in ["type_a", "type_b", "type_a"]:
            telemetry_client.post(
                "/v1/events",
                json={
                    "event_id": f"evt-{event_type}",
                    "trace_id": "trace-filter",
                    "event_type": event_type,
                },
            )

        response = telemetry_client.get("/v1/events", params={"event_type": "type_a"})
        assert response.status_code == 200
        assert response.json()["count"] == 2

    def test_event_not_found(self, telemetry_client: TestClient):
        """Test getting non-existent event."""
        response = telemetry_client.get("/v1/events/nonexistent")
        assert response.status_code == 404
