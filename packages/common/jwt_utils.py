"""JWT utilities for agent identity tokens."""

import hashlib
import os
import time
import uuid
from typing import Any

import jwt

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRY_SECONDS = int(os.environ.get("JWT_EXPIRY_SECONDS", "300"))

_revocation_list: set[str] = set()


def create_token(
    user: str,
    agent_identity: str,
    agent_instance_id: str,
    task_id: str,
    intent: str,
    device_id: str,
    audience: str = "agentic-endpoint-security",
    scope: list[str] | None = None,
    tool_id: str = "",
    tool_version: str = "",
    resource: str = "",
    expiry_seconds: int | None = None,
) -> tuple[str, dict[str, Any]]:
    """
    Create a short-lived JWT for agent identity.

    Returns tuple of (token_string, claims_dict).

    Token lifetime is 5 minutes (300s) by default per spec.
    No PAT passthrough - tokens are purpose-built with attenuated scope.
    """
    now = int(time.time())
    exp_seconds = expiry_seconds if expiry_seconds is not None else JWT_EXPIRY_SECONDS
    jti = str(uuid.uuid4())

    intent_hash = hashlib.sha256(intent.encode()).hexdigest()[:16]

    claims = {
        "iss": "agentic-endpoint-security",
        "sub": user,
        "act": {"sub": agent_identity},
        "aud": audience,
        "scope": scope or [],
        "device_id": device_id,
        "agent_instance_id": agent_instance_id,
        "task_id": task_id,
        "intent_hash": intent_hash,
        "tool_id": tool_id,
        "tool_version": tool_version,
        "resource": resource,
        "jti": jti,
        "iat": now,
        "exp": now + exp_seconds,
    }

    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, claims


def verify_token(token: str, audience: str = "agentic-endpoint-security") -> dict[str, Any]:
    """
    Verify and decode a JWT.

    Raises:
        jwt.InvalidTokenError: If token is invalid, expired, or revoked.
    """
    claims = jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        audience=audience,
    )

    if is_token_revoked(claims.get("jti", "")):
        raise jwt.InvalidTokenError("Token has been revoked")

    return claims


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode a JWT without verification (for inspection only).

    WARNING: Do not use for authorization decisions.
    """
    return jwt.decode(token, options={"verify_signature": False})


def is_token_revoked(jti: str) -> bool:
    """Check if a token ID is in the revocation list."""
    return jti in _revocation_list


def revoke_token(jti: str) -> None:
    """
    Add a token ID to the revocation list.

    Production note: This uses in-memory storage. For production,
    use Redis or a distributed cache with TTL matching max token lifetime.
    """
    _revocation_list.add(jti)


def revoke_tokens_for_agent(agent_identity: str, tokens: list[dict[str, Any]]) -> int:
    """
    Revoke all tokens for a specific agent.

    Returns count of tokens revoked.
    """
    count = 0
    for token_info in tokens:
        if token_info.get("agent_identity") == agent_identity:
            jti = token_info.get("jti")
            if jti:
                revoke_token(jti)
                count += 1
    return count


def clear_revocation_list() -> None:
    """Clear the revocation list (for testing only)."""
    _revocation_list.clear()


def get_revocation_list() -> set[str]:
    """Get current revocation list (for testing/debugging)."""
    return _revocation_list.copy()
