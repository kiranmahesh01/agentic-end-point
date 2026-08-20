"""Pytest configuration and fixtures."""

import os
import pytest
from fastapi.testclient import TestClient


os.environ["JWT_SECRET"] = "test-secret"
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["JWT_EXPIRY_SECONDS"] = "300"
os.environ["APPROVAL_HMAC_SECRET"] = "test-hmac-secret"
os.environ["APPROVED_READ_ROOTS"] = "/approved/workspace,/tmp/approved"
os.environ["APPROVED_WRITE_ROOTS"] = "/approved/output"


@pytest.fixture
def registry_client():
    """Create a test client for the registry service."""
    from services.registry.app import app, _components, _seed_demo_components

    _components.clear()
    _seed_demo_components()

    with TestClient(app) as client:
        yield client


@pytest.fixture
def pdp_client():
    """Create a test client for the PDP service."""
    from services.pdp.app import app

    with TestClient(app) as client:
        yield client


@pytest.fixture
def identity_client():
    """Create a test client for the identity service."""
    from services.identity.app import app, _issued_tokens
    from packages.common.jwt_utils import clear_revocation_list

    _issued_tokens.clear()
    clear_revocation_list()

    with TestClient(app) as client:
        yield client


@pytest.fixture
def broker_client():
    """Create a test client for the broker service."""
    from services.broker.app import app, clear_terminated_tasks, _local_cache

    clear_terminated_tasks()
    _local_cache.clear()

    with TestClient(app) as client:
        yield client


@pytest.fixture
def approval_client():
    """Create a test client for the approval service."""
    from services.approval.app import app, _approvals

    _approvals.clear()

    with TestClient(app) as client:
        yield client


@pytest.fixture
def telemetry_client():
    """Create a test client for the telemetry service."""
    from services.telemetry.app import app, _events

    _events.clear()

    with TestClient(app) as client:
        yield client


@pytest.fixture
def killswitch_client():
    """Create a test client for the kill switch service."""
    from services.killswitch.app import app, _kill_history

    _kill_history.clear()

    with TestClient(app) as client:
        yield client


@pytest.fixture
def demo_agent_client():
    """Create a test client for the demo agent."""
    from services.demo_agent.app import app

    with TestClient(app) as client:
        yield client


@pytest.fixture
def valid_action_request():
    """Return a valid action request dict."""
    return {
        "user": "test-user",
        "agent_identity": "agent:demo-coder",
        "agent_instance": "instance-123",
        "agent_version": "1.0.0",
        "endpoint_id": "endpoint-001",
        "task_id": "task-123",
        "declared_goal": "Test operation",
        "tool_id": "test-tool",
        "tool_version": "1.0.0",
        "tool_definition_hash": "sha256:demo-coder-definition-hash-def456",
        "requested_operation": "read_file",
        "target_resource": "/approved/workspace/test.txt",
        "input_source": "test",
        "input_trust": "trusted",
        "data_classification": "internal",
    }
