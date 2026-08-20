"""Data models for Agentic Endpoint Security."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ComponentType(str, Enum):
    """Type of component in the registry."""

    AGENT = "agent"
    SKILL = "skill"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    EXTENSION = "extension"
    MODEL_ARTIFACT = "model_artifact"


class LifecycleStatus(str, Enum):
    """Lifecycle status of a component."""

    PROPOSED = "proposed"
    APPROVED = "approved"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class ApprovalStatus(str, Enum):
    """Approval status of a component."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class RiskTier(int, Enum):
    """Risk tier for components (0-4, higher = more risk)."""

    TIER_0 = 0  # Minimal risk, pre-approved operations
    TIER_1 = 1  # Low risk, standard operations
    TIER_2 = 2  # Medium risk, requires monitoring
    TIER_3 = 3  # High risk, requires approval
    TIER_4 = 4  # Critical risk, restricted operations


class Decision(str, Enum):
    """Policy decision outcome."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ALLOW_IN_SANDBOX = "ALLOW_IN_SANDBOX"
    ISSUE_EPHEMERAL_CREDENTIAL = "ISSUE_EPHEMERAL_CREDENTIAL"
    TERMINATE_AND_REVOKE = "TERMINATE_AND_REVOKE"


class InputTrust(str, Enum):
    """Trust level of input data."""

    TRUSTED = "trusted"
    INTERNAL = "internal"
    UNTRUSTED = "untrusted"


class Permissions(BaseModel):
    """Permissions granted to a component."""

    files_read: list[str] = Field(default_factory=list)
    files_write: list[str] = Field(default_factory=list)
    shell: bool = False
    network_allowlist: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)
    computer_use: bool = Field(
        default=False,
        description="Permission to use isolated desktop automation (never the operator's real desktop)"
    )


class Autonomy(BaseModel):
    """Autonomy settings for a component."""

    can_execute_without_approval: bool = False
    can_access_network: bool = False
    can_modify_files: bool = False
    can_spawn_processes: bool = False
    can_access_secrets: bool = False


class Component(BaseModel):
    """A registered component (agent, skill, tool, etc.)."""

    id: str = Field(..., description="Unique component identifier (e.g., agent:demo-coder)")
    type: ComponentType
    owner: str = Field(..., description="Owner identity (user or team)")
    purpose: str = Field(..., description="Description of component purpose")
    publisher: str = Field(..., description="Publisher identity")
    version: str = Field(..., description="Semantic version")
    content_hash: str = Field(..., description="SHA-256 hash of component content")
    definition_hash: str = Field(..., description="SHA-256 hash of component definition")
    signature_status: str = Field(default="unsigned", description="Signature verification status")
    risk_tier: RiskTier = Field(default=RiskTier.TIER_2)
    approval_status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    approval_expiry: datetime | None = None
    permissions: Permissions = Field(default_factory=Permissions)
    autonomy: Autonomy = Field(default_factory=Autonomy)
    lifecycle: LifecycleStatus = Field(default=LifecycleStatus.PROPOSED)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ActionRequest(BaseModel):
    """Request for an action to be authorized by the PDP."""

    user: str = Field(..., description="User identity")
    agent_identity: str = Field(..., description="Agent component ID")
    agent_instance: str = Field(..., description="Unique instance ID for this agent run")
    agent_version: str = Field(..., description="Agent version")
    endpoint_id: str = Field(..., description="Endpoint/device identifier")
    task_id: str = Field(..., description="Current task identifier")
    declared_goal: str = Field(..., description="Agent's declared goal for this action")
    tool_id: str = Field(..., description="Tool being invoked")
    tool_version: str = Field(..., description="Tool version")
    tool_definition_hash: str = Field(..., description="Hash of loaded tool definition")
    requested_operation: str = Field(..., description="Operation type (read_file, write_file, etc.)")
    target_resource: str = Field(..., description="Target resource path or identifier")
    arguments: dict[str, Any] = Field(default_factory=dict)
    input_source: str = Field(default="", description="Source of input data")
    input_trust: InputTrust = Field(default=InputTrust.UNTRUSTED)
    data_classification: str = Field(default="unclassified")
    destination: str = Field(default="", description="Network destination if applicable")
    budget_state: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None


class ActionResponse(BaseModel):
    """Response from the PDP or broker."""

    decision: Decision
    reason: str = Field(..., description="Human-readable reason for decision")
    request_id: str = Field(..., description="Unique request identifier")
    approval_id: str | None = Field(None, description="Approval ID if REQUIRE_APPROVAL")
    constraints: dict[str, Any] = Field(default_factory=dict)
    credential: dict[str, Any] | None = Field(None, description="Ephemeral credential if issued")
    telemetry_id: str | None = None


class TokenClaims(BaseModel):
    """JWT token claims for agent identity."""

    iss: str = Field(..., description="Issuer")
    sub: str = Field(..., description="Subject (user)")
    act_sub: str = Field(..., description="Acting subject (agent)")
    aud: str = Field(..., description="Audience")
    scope: list[str] = Field(default_factory=list)
    device_id: str = Field(..., description="Device identifier")
    agent_instance_id: str = Field(..., description="Agent instance identifier")
    task_id: str = Field(..., description="Current task identifier")
    intent_hash: str = Field(..., description="Hash of declared intent")
    tool_id: str = Field(default="", description="Authorized tool")
    tool_version: str = Field(default="", description="Authorized tool version")
    resource: str = Field(default="", description="Authorized resource")
    jti: str = Field(..., description="Unique token identifier")
    iat: int = Field(..., description="Issued at timestamp")
    exp: int = Field(..., description="Expiration timestamp")


class ApprovalRecord(BaseModel):
    """Record of a pending or completed approval."""

    approval_id: str = Field(..., description="HMAC-signed approval identifier")
    user: str
    agent_identity: str
    agent_version: str
    endpoint_id: str
    task_id: str
    requested_operation: str
    target_resource: str
    data_classification: str
    destination: str
    diff: str | None = Field(None, description="Diff content for write operations")
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    decided_at: datetime | None = None
    decided_by: str | None = None
    reason: str | None = None


class TelemetryEvent(BaseModel):
    """Telemetry event for auditing."""

    event_id: str
    trace_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    user: str | None = None
    agent_identity: str | None = None
    agent_instance: str | None = None
    endpoint_id: str | None = None
    task_id: str | None = None
    operation: str | None = None
    target: str | None = None
    decision: Decision | None = None
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class KillSwitchRequest(BaseModel):
    """Request to activate kill switch."""

    agent_id: str = Field(..., description="Agent to terminate")
    task_ids: list[str] = Field(default_factory=list, description="Specific task IDs to terminate")
    reason: str = Field(..., description="Reason for kill switch activation")
    initiated_by: str = Field(default="operator", description="Who initiated the kill")


class KillSwitchStatus(BaseModel):
    """Status of kill switch activation."""

    kill_id: str
    agent_id: str
    status: str
    registry_suspended: bool = False
    tokens_revoked: bool = False
    tasks_terminated: list[str] = Field(default_factory=list)
    edr_isolate_logged: bool = False
    egress_deny_logged: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    errors: list[str] = Field(default_factory=list)
