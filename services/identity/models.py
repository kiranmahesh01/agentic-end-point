"""Identity service models."""

from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    """Request for a new agent identity token."""

    user: str = Field(..., description="User identity")
    agent_identity: str = Field(..., description="Agent component ID")
    agent_instance_id: str = Field(..., description="Unique instance ID")
    task_id: str = Field(..., description="Current task identifier")
    intent: str = Field(..., description="Declared intent for this token")
    device_id: str = Field(..., description="Device identifier")
    audience: str = Field(default="agentic-endpoint-security")
    scope: list[str] = Field(default_factory=list)
    tool_id: str = Field(default="")
    tool_version: str = Field(default="")
    resource: str = Field(default="")


class TokenResponse(BaseModel):
    """Response containing the issued token."""

    token: str
    token_type: str = "Bearer"
    expires_in: int
    jti: str
    issued_at: int


class RevokeRequest(BaseModel):
    """Request to revoke a token."""

    jti: str = Field(..., description="Token ID to revoke")
    reason: str = Field(default="Manual revocation")


class RevokeResponse(BaseModel):
    """Response from token revocation."""

    success: bool
    message: str
    jti: str


class TokenInfo(BaseModel):
    """Information about an issued token (for tracking)."""

    jti: str
    user: str
    agent_identity: str
    agent_instance_id: str
    task_id: str
    issued_at: int
    expires_at: int
    revoked: bool = False
