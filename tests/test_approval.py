"""Tests for the approval service."""

import pytest
from fastapi.testclient import TestClient


class TestApproval:
    """Tests for approval service."""

    def test_health_check(self, approval_client: TestClient):
        """Test health endpoint."""
        response = approval_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_create_approval(self, approval_client: TestClient):
        """Test creating an approval request."""
        request = {
            "user": "test-user",
            "agent_identity": "agent:demo-coder",
            "agent_version": "1.0.0",
            "endpoint_id": "endpoint-001",
            "task_id": "task-123",
            "requested_operation": "write_file",
            "target_resource": "/approved/output/report.txt",
            "data_classification": "internal",
            "destination": "",
            "diff": "--- a/report.txt\n+++ b/report.txt\n@@ -1 +1 @@\n-old\n+new",
        }

        response = approval_client.post("/v1/approvals", json=request)
        assert response.status_code == 201

        data = response.json()
        assert data["status"] == "pending"
        assert data["approval_id"].startswith("apr-")
        assert data["user"] == "test-user"

    def test_get_approval(self, approval_client: TestClient):
        """Test getting an approval by ID."""
        create_response = approval_client.post(
            "/v1/approvals",
            json={
                "user": "test-user",
                "agent_identity": "agent:demo-coder",
                "agent_version": "1.0.0",
                "endpoint_id": "endpoint-001",
                "task_id": "task-123",
                "requested_operation": "write_file",
                "target_resource": "/approved/output/test.txt",
            },
        )
        approval_id = create_response.json()["approval_id"]

        response = approval_client.get(f"/v1/approvals/{approval_id}")
        assert response.status_code == 200
        assert response.json()["approval_id"] == approval_id

    def test_approve_request(self, approval_client: TestClient):
        """Test approving a request."""
        create_response = approval_client.post(
            "/v1/approvals",
            json={
                "user": "test-user",
                "agent_identity": "agent:demo-coder",
                "agent_version": "1.0.0",
                "endpoint_id": "endpoint-001",
                "task_id": "task-123",
                "requested_operation": "write_file",
                "target_resource": "/approved/output/test.txt",
            },
        )
        approval_id = create_response.json()["approval_id"]

        decide_response = approval_client.post(
            f"/v1/approvals/{approval_id}/decide",
            json={
                "approved": True,
                "decided_by": "security-admin",
                "reason": "Verified safe operation",
            },
        )
        assert decide_response.status_code == 200

        data = decide_response.json()
        assert data["status"] == "approved"
        assert data["decided_by"] == "security-admin"

    def test_deny_request(self, approval_client: TestClient):
        """Test denying a request."""
        create_response = approval_client.post(
            "/v1/approvals",
            json={
                "user": "test-user",
                "agent_identity": "agent:demo-coder",
                "agent_version": "1.0.0",
                "endpoint_id": "endpoint-001",
                "task_id": "task-123",
                "requested_operation": "write_file",
                "target_resource": "/approved/output/test.txt",
            },
        )
        approval_id = create_response.json()["approval_id"]

        decide_response = approval_client.post(
            f"/v1/approvals/{approval_id}/decide",
            json={
                "approved": False,
                "decided_by": "security-admin",
                "reason": "Suspicious operation",
            },
        )
        assert decide_response.status_code == 200

        data = decide_response.json()
        assert data["status"] == "denied"

    def test_cannot_decide_twice(self, approval_client: TestClient):
        """Test that approvals cannot be decided twice."""
        create_response = approval_client.post(
            "/v1/approvals",
            json={
                "user": "test-user",
                "agent_identity": "agent:demo-coder",
                "agent_version": "1.0.0",
                "endpoint_id": "endpoint-001",
                "task_id": "task-123",
                "requested_operation": "write_file",
                "target_resource": "/approved/output/test.txt",
            },
        )
        approval_id = create_response.json()["approval_id"]

        approval_client.post(
            f"/v1/approvals/{approval_id}/decide",
            json={
                "approved": True,
                "decided_by": "admin1",
                "reason": "OK",
            },
        )

        second_response = approval_client.post(
            f"/v1/approvals/{approval_id}/decide",
            json={
                "approved": False,
                "decided_by": "admin2",
                "reason": "Changed mind",
            },
        )
        assert second_response.status_code == 409

    def test_list_approvals(self, approval_client: TestClient):
        """Test listing approvals."""
        for i in range(3):
            approval_client.post(
                "/v1/approvals",
                json={
                    "user": "test-user",
                    "agent_identity": "agent:demo-coder",
                    "agent_version": "1.0.0",
                    "endpoint_id": "endpoint-001",
                    "task_id": f"task-{i}",
                    "requested_operation": "write_file",
                    "target_resource": f"/approved/output/test{i}.txt",
                },
            )

        response = approval_client.get("/v1/approvals")
        assert response.status_code == 200
        assert response.json()["count"] == 3

    def test_invalid_approval_id_format(self, approval_client: TestClient):
        """Test that invalid approval ID format is rejected."""
        response = approval_client.get("/v1/approvals/invalid-id")
        assert response.status_code == 400
