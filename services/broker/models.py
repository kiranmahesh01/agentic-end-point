"""Broker-specific models for typed adapters."""

from typing import Any
from pydantic import BaseModel, Field

from packages.common.models import Decision, InputTrust


class BaseAdapterRequest(BaseModel):
    """Base request for all adapter operations."""

    user: str
    agent_identity: str
    agent_instance: str
    agent_version: str
    endpoint_id: str
    task_id: str
    declared_goal: str
    tool_id: str
    tool_version: str
    tool_definition_hash: str
    input_source: str = ""
    input_trust: InputTrust = InputTrust.UNTRUSTED
    data_classification: str = "unclassified"
    budget_state: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None


class ReadFileRequest(BaseAdapterRequest):
    """Request to read a file."""

    path: str = Field(..., description="Path to read")


class WriteFileRequest(BaseAdapterRequest):
    """Request to write a file."""

    path: str = Field(..., description="Path to write")
    content: str = Field(..., description="Content to write")


class RunCommandRequest(BaseAdapterRequest):
    """
    Request to run a command.

    IMPORTANT: This is NOT a raw shell endpoint.
    Commands are specified by command_id with typed arguments.
    """

    command_id: str = Field(..., description="Registered command identifier")
    args: dict[str, Any] = Field(default_factory=dict, description="Typed command arguments")


class HttpRequestData(BaseAdapterRequest):
    """Request to make an HTTP request."""

    service_id: str = Field(..., description="Registered service identifier")
    method: str = Field(default="GET")
    path: str = Field(default="/")
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    destination: str = Field(..., description="Target host/domain")


class LoadModelRequest(BaseAdapterRequest):
    """Request to load a model artifact."""

    model_id: str = Field(..., description="Model identifier")
    version: str = Field(..., description="Model version")


class AdapterResponse(BaseModel):
    """Response from an adapter operation."""

    success: bool
    decision: Decision
    reason: str
    request_id: str
    result: Any = None
    approval_id: str | None = None
    telemetry_id: str | None = None
