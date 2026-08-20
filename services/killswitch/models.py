"""Kill switch service models."""

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any


class KillRequest(BaseModel):
    """Request to activate kill switch."""

    agent_id: str = Field(..., description="Agent to terminate")
    task_ids: list[str] = Field(default_factory=list, description="Specific tasks to terminate")
    reason: str = Field(..., description="Reason for kill switch")
    initiated_by: str = Field(default="operator")


class KillStatus(BaseModel):
    """Status of a kill switch activation."""

    kill_id: str
    agent_id: str
    status: str
    initiated_by: str
    reason: str
    timestamp: datetime
    registry_suspended: bool = False
    tokens_revoked: int = 0
    tasks_terminated: list[str] = Field(default_factory=list)
    edr_isolate_logged: bool = False
    egress_deny_logged: bool = False
    errors: list[str] = Field(default_factory=list)
