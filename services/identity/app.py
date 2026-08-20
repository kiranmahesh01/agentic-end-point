"""
Identity Service

Port: 8083

Issues and manages short-lived JWT tokens for agent identities.
Each token is scoped to a specific user, agent, task, and optionally tool/resource.

Key principles:
- 5-minute token lifetime (300 seconds)
- No PAT passthrough - tokens are purpose-built
- In-memory revocation list (Redis for production)
- Distinct agent + instance identities

Production note: Use org IdP + RFC 8693 token exchange in production.
"""

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, status

from packages.common.jwt_utils import (
    create_token,
    verify_token,
    revoke_token,
    is_token_revoked,
    get_revocation_list,
    clear_revocation_list,
    JWT_EXPIRY_SECONDS,
)
from services.identity.models import (
    TokenRequest,
    TokenResponse,
    RevokeRequest,
    RevokeResponse,
    TokenInfo,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Identity",
    description="Agent identity token service. 5-minute tokens. No PAT passthrough.",
    version="0.1.0",
)

_issued_tokens: dict[str, TokenInfo] = {}


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "identity"}


@app.post("/v1/token", response_model=TokenResponse)
async def issue_token(request: TokenRequest) -> TokenResponse:
    """
    Issue a short-lived JWT for an agent identity.

    Tokens are valid for 5 minutes (300 seconds) and scoped to:
    - User identity
    - Agent identity
    - Agent instance
    - Task ID
    - Intent hash
    - Optionally: tool, resource

    No PAT passthrough - this is not a credential relay.
    Production deployments should use RFC 8693 token exchange with the org IdP.
    """
    token, claims = create_token(
        user=request.user,
        agent_identity=request.agent_identity,
        agent_instance_id=request.agent_instance_id,
        task_id=request.task_id,
        intent=request.intent,
        device_id=request.device_id,
        audience=request.audience,
        scope=request.scope,
        tool_id=request.tool_id,
        tool_version=request.tool_version,
        resource=request.resource,
    )

    jti = claims["jti"]
    iat = claims["iat"]
    exp = claims["exp"]

    _issued_tokens[jti] = TokenInfo(
        jti=jti,
        user=request.user,
        agent_identity=request.agent_identity,
        agent_instance_id=request.agent_instance_id,
        task_id=request.task_id,
        issued_at=iat,
        expires_at=exp,
        revoked=False,
    )

    logger.info(
        f"Issued token {jti[:8]}... for {request.agent_identity} "
        f"(user={request.user}, task={request.task_id})"
    )

    return TokenResponse(
        token=token,
        token_type="Bearer",
        expires_in=JWT_EXPIRY_SECONDS,
        jti=jti,
        issued_at=iat,
    )


@app.post("/v1/revoke", response_model=RevokeResponse)
async def revoke(request: RevokeRequest) -> RevokeResponse:
    """
    Revoke a token by JTI.

    Revoked tokens are rejected by verify_token.
    This uses in-memory storage; production should use Redis with TTL.
    """
    if is_token_revoked(request.jti):
        return RevokeResponse(
            success=True,
            message="Token already revoked",
            jti=request.jti,
        )

    revoke_token(request.jti)

    if request.jti in _issued_tokens:
        _issued_tokens[request.jti].revoked = True

    logger.warning(f"Revoked token {request.jti[:8]}...: {request.reason}")

    return RevokeResponse(
        success=True,
        message=f"Token revoked: {request.reason}",
        jti=request.jti,
    )


@app.post("/v1/revoke-agent")
async def revoke_agent_tokens(agent_identity: str, reason: str = "Agent revocation") -> dict[str, Any]:
    """
    Revoke all tokens for a specific agent identity.

    Used by the kill switch to immediately invalidate all tokens for an agent.
    """
    revoked_count = 0

    for jti, token_info in _issued_tokens.items():
        if token_info.agent_identity == agent_identity and not token_info.revoked:
            revoke_token(jti)
            token_info.revoked = True
            revoked_count += 1

    logger.warning(f"Revoked {revoked_count} tokens for agent {agent_identity}: {reason}")

    return {
        "success": True,
        "agent_identity": agent_identity,
        "tokens_revoked": revoked_count,
        "reason": reason,
    }


@app.get("/v1/verify")
async def verify(token: str) -> dict[str, Any]:
    """
    Verify a token and return its claims.

    Returns error if token is invalid, expired, or revoked.
    """
    try:
        claims = verify_token(token)
        return {
            "valid": True,
            "claims": claims,
        }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
        }


@app.get("/v1/tokens")
async def list_tokens(agent_identity: str | None = None) -> dict[str, Any]:
    """
    List issued tokens (for debugging/auditing).

    Optionally filter by agent identity.
    """
    tokens = list(_issued_tokens.values())

    if agent_identity:
        tokens = [t for t in tokens if t.agent_identity == agent_identity]

    return {
        "count": len(tokens),
        "tokens": [t.model_dump() for t in tokens],
    }


@app.get("/v1/revocation-list")
async def get_revocations() -> dict[str, Any]:
    """Get the current revocation list (for debugging)."""
    revoked = get_revocation_list()
    return {
        "count": len(revoked),
        "revoked_jtis": list(revoked),
    }


@app.delete("/v1/tokens")
async def clear_tokens() -> dict[str, str]:
    """Clear all tokens and revocation list (for testing only)."""
    _issued_tokens.clear()
    clear_revocation_list()
    logger.warning("Cleared all tokens and revocation list")
    return {"message": "All tokens cleared"}


def get_issued_tokens() -> dict[str, TokenInfo]:
    """Get issued tokens store (for testing)."""
    return _issued_tokens


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8083)
