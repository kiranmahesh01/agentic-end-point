"""IdP service models."""

from pydantic import BaseModel, Field
from typing import Any


class TokenExchangeRequest(BaseModel):
    """RFC 8693 Token Exchange request."""
    
    grant_type: str = Field(
        default="urn:ietf:params:oauth:grant-type:token-exchange",
        description="Must be token-exchange grant type"
    )
    subject_token: str = Field(..., description="The user's authentication token")
    subject_token_type: str = Field(
        default="urn:ietf:params:oauth:token-type:access_token",
        description="Type of subject token"
    )
    requested_token_type: str = Field(
        default="urn:ietf:params:oauth:token-type:access_token",
        description="Type of token to issue"
    )
    audience: str = Field(default="agentic-endpoint-security")
    scope: str = Field(default="")
    actor_token: str | None = Field(None, description="Agent identity token")
    actor_token_type: str | None = Field(None)


class AgentTokenRequest(BaseModel):
    """Request for an agent-scoped token (simplified for demo)."""
    
    user: str = Field(..., description="User identity")
    agent_identity: str = Field(..., description="Agent component ID")
    agent_instance_id: str = Field(..., description="Unique instance ID")
    task_id: str = Field(..., description="Current task identifier")
    intent: str = Field(..., description="Declared intent for this token")
    device_id: str = Field(..., description="Device identifier")
    scope: list[str] = Field(default_factory=list)
    tool_id: str = Field(default="")
    tool_version: str = Field(default="")
    resource: str = Field(default="")


class TokenResponse(BaseModel):
    """Token response following OAuth 2.0 format."""
    
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str = ""
    issued_token_type: str = "urn:ietf:params:oauth:token-type:access_token"


class JWK(BaseModel):
    """JSON Web Key representation."""
    
    kty: str
    use: str = "sig"
    kid: str
    alg: str
    n: str | None = None
    e: str | None = None


class JWKS(BaseModel):
    """JSON Web Key Set."""
    
    keys: list[JWK]


class RevokeRequest(BaseModel):
    """Token revocation request."""
    
    token: str = Field(..., description="Token to revoke (or JTI)")
    token_type_hint: str = Field(default="access_token")
