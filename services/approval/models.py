"""Approval service models."""

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any

from packages.common.models import ApprovalStatus


class ApprovalCreate(BaseModel):
    """Request to create a new approval."""

    user: str
    agent_identity: str
    agent_version: str
    endpoint_id: str
    task_id: str
    requested_operation: str
    target_resource: str
    data_classification: str = "unclassified"
    destination: str = ""
    diff: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(BaseModel):
    """Decision on an approval request."""

    approved: bool
    decided_by: str
    reason: str = ""


class ApprovalResponse(BaseModel):
    """Response from approval operations."""

    approval_id: str
    status: ApprovalStatus
    user: str
    agent_identity: str
    agent_version: str
    endpoint_id: str
    task_id: str
    requested_operation: str
    target_resource: str
    data_classification: str
    destination: str
    diff: str | None
    created_at: datetime
    decided_at: datetime | None
    decided_by: str | None
    reason: str | None
