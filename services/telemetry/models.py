"""Telemetry service models."""

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    """Request to create a telemetry event."""

    event_id: str
    trace_id: str
    event_type: str
    user: str | None = None
    agent_identity: str | None = None
    agent_instance: str | None = None
    endpoint_id: str | None = None
    task_id: str | None = None
    operation: str | None = None
    target: str | None = None
    decision: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventResponse(BaseModel):
    """Response containing event details."""

    event_id: str
    trace_id: str
    timestamp: datetime
    event_type: str
    user: str | None
    agent_identity: str | None
    agent_instance: str | None
    endpoint_id: str | None
    task_id: str | None
    operation: str | None
    target: str | None
    decision: str | None
    reason: str | None
    metadata: dict[str, Any]
