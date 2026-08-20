"""PDP-specific models."""

from pydantic import BaseModel, Field
from typing import Any

from packages.common.models import Decision


class PolicyDecision(BaseModel):
    """Full policy decision with context."""

    decision: Decision
    reason: str
    request_id: str
    component_verified: bool = False
    hash_verified: bool = False
    permissions_checked: bool = False
    path_safe: bool = False
    egress_allowed: bool = False
    approval_id: str | None = None
    constraints: dict[str, Any] = Field(default_factory=dict)


class PolicyConfig(BaseModel):
    """Loaded policy configuration."""

    version: str
    description: str
    default_decision: str
    required_fields: list[str]
    class_a_operations: list[str]
    class_b_operations: list[str]
    class_c_operations: list[str]
