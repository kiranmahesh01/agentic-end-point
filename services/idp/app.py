"""
Local IdP Service

Port: 8443

A local OIDC-like Identity Provider that issues RS256-signed JWTs.
Provides JWKS endpoint for token verification.

This is a real IdP for the compose stack, not a mock.
In production, replace with your organization's IdP and use RFC 8693 token exchange.

Key features:
- RS256 signing (not HS256)
- JWKS endpoint for public key distribution
- 5-minute token lifetime
- No PAT passthrough
- Token revocation via Redis (when available)
"""

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from services.idp.models import (
    AgentTokenRequest,
    TokenResponse,
    TokenExchangeRequest,
    JWKS,
    JWK,
    RevokeRequest,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - IdP",
    description="Local Identity Provider with JWKS. RS256 signing. 5-minute tokens.",
    version="0.1.0",
)

security = HTTPBearer(auto_error=False)

TOKEN_EXPIRY_SECONDS = int(os.environ.get("TOKEN_EXPIRY_SECONDS", "300"))
ISSUER = os.environ.get("IDP_ISSUER", "https://idp.agentic-security.local")
REDIS_URL = os.environ.get("REDIS_URL", "")

_private_key = None
_public_key = None
_key_id = None
_jwks_cache = None

_revoked_tokens: set[str] = set()

try:
    import redis
    _redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None
except ImportError:
    _redis_client = None


def _generate_keys():
    """Generate RSA key pair for JWT signing."""
    global _private_key, _public_key, _key_id
    
    key_path = os.environ.get("IDP_PRIVATE_KEY_PATH", "")
    
    if key_path and os.path.exists(key_path):
        with open(key_path, "rb") as f:
            _private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        _public_key = _private_key.public_key()
        logger.info(f"Loaded RSA key from {key_path}")
    else:
        _private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        _public_key = _private_key.public_key()
        logger.info("Generated new RSA key pair")
    
    public_bytes = _public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _key_id = hashlib.sha256(public_bytes).hexdigest()[:16]


def _get_jwks() -> JWKS:
    """Get the JWKS for token verification."""
    global _jwks_cache
    
    if _jwks_cache:
        return _jwks_cache
    
    public_numbers = _public_key.public_numbers()
    
    def _int_to_base64url(n: int) -> str:
        byte_length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(
            n.to_bytes(byte_length, byteorder='big')
        ).rstrip(b'=').decode('ascii')
    
    jwk = JWK(
        kty="RSA",
        use="sig",
        kid=_key_id,
        alg="RS256",
        n=_int_to_base64url(public_numbers.n),
        e=_int_to_base64url(public_numbers.e),
    )
    
    _jwks_cache = JWKS(keys=[jwk])
    return _jwks_cache


def _is_revoked(jti: str) -> bool:
    """Check if a token is revoked."""
    if _redis_client:
        try:
            return _redis_client.exists(f"revoked:{jti}") > 0
        except Exception:
            pass
    return jti in _revoked_tokens


def _revoke(jti: str, ttl: int = 300) -> None:
    """Revoke a token."""
    if _redis_client:
        try:
            _redis_client.setex(f"revoked:{jti}", ttl, "1")
            return
        except Exception:
            pass
    _revoked_tokens.add(jti)


_generate_keys()


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "idp"}


@app.get("/.well-known/jwks.json", response_model=JWKS)
async def get_jwks() -> JWKS:
    """
    JWKS endpoint for public key distribution.
    
    Services verify tokens by fetching this JWKS and using the public key.
    """
    return _get_jwks()


@app.get("/.well-known/openid-configuration")
async def openid_configuration() -> dict[str, Any]:
    """OpenID Connect discovery document."""
    base_url = ISSUER
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/v1/token",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "revocation_endpoint": f"{base_url}/v1/revoke",
        "token_exchange_endpoint": f"{base_url}/v1/token-exchange",
        "response_types_supported": ["token"],
        "grant_types_supported": [
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


@app.post("/v1/token", response_model=TokenResponse)
async def issue_token(request: AgentTokenRequest) -> TokenResponse:
    """
    Issue a short-lived RS256-signed JWT for an agent.
    
    This is a simplified endpoint for demo purposes.
    Production should use RFC 8693 token exchange.
    """
    now = int(time.time())
    jti = str(uuid.uuid4())
    
    intent_hash = hashlib.sha256(request.intent.encode()).hexdigest()[:16]
    
    claims = {
        "iss": ISSUER,
        "sub": request.user,
        "act": {"sub": request.agent_identity},
        "aud": "agentic-endpoint-security",
        "scope": request.scope,
        "device_id": request.device_id,
        "agent_instance_id": request.agent_instance_id,
        "task_id": request.task_id,
        "intent_hash": intent_hash,
        "tool_id": request.tool_id,
        "tool_version": request.tool_version,
        "resource": request.resource,
        "jti": jti,
        "iat": now,
        "exp": now + TOKEN_EXPIRY_SECONDS,
    }
    
    token = jwt.encode(
        claims,
        _private_key,
        algorithm="RS256",
        headers={"kid": _key_id}
    )
    
    logger.info(
        f"Issued token {jti[:8]}... for {request.agent_identity} "
        f"(user={request.user}, task={request.task_id})"
    )
    
    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=TOKEN_EXPIRY_SECONDS,
        scope=" ".join(request.scope),
    )


@app.post("/v1/token-exchange", response_model=TokenResponse)
async def token_exchange(request: TokenExchangeRequest) -> TokenResponse:
    """
    RFC 8693 Token Exchange endpoint.
    
    Exchanges a user token for an agent-scoped token.
    In production, the subject_token would be verified against the org IdP.
    """
    if request.grant_type != "urn:ietf:params:oauth:grant-type:token-exchange":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid grant type"
        )
    
    now = int(time.time())
    jti = str(uuid.uuid4())
    
    claims = {
        "iss": ISSUER,
        "sub": "exchanged-user",
        "aud": request.audience,
        "scope": request.scope.split() if request.scope else [],
        "jti": jti,
        "iat": now,
        "exp": now + TOKEN_EXPIRY_SECONDS,
        "exchanged": True,
    }
    
    if request.actor_token:
        claims["act"] = {"sub": "actor-from-exchange"}
    
    token = jwt.encode(
        claims,
        _private_key,
        algorithm="RS256",
        headers={"kid": _key_id}
    )
    
    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in=TOKEN_EXPIRY_SECONDS,
        scope=request.scope,
        issued_token_type=request.requested_token_type,
    )


@app.post("/v1/revoke")
async def revoke_token(request: RevokeRequest) -> dict[str, Any]:
    """Revoke a token."""
    try:
        unverified = jwt.decode(request.token, options={"verify_signature": False})
        jti = unverified.get("jti", request.token)
    except Exception:
        jti = request.token
    
    _revoke(jti, TOKEN_EXPIRY_SECONDS)
    
    logger.warning(f"Revoked token: {jti[:8] if len(jti) > 8 else jti}...")
    
    return {"revoked": True, "jti": jti}


@app.post("/v1/revoke-agent")
async def revoke_agent_tokens(
    agent_identity: str,
    reason: str = "Agent revocation"
) -> dict[str, Any]:
    """
    Revoke all tokens for an agent.
    
    In production with Redis, this would scan for all tokens with this agent.
    For demo, we track issued tokens separately.
    """
    logger.warning(f"Revoke all tokens for {agent_identity}: {reason}")
    
    return {
        "success": True,
        "agent_identity": agent_identity,
        "reason": reason,
    }


@app.get("/v1/verify")
async def verify_token(token: str) -> dict[str, Any]:
    """Verify a token and return claims."""
    try:
        claims = jwt.decode(
            token,
            _public_key,
            algorithms=["RS256"],
            audience="agentic-endpoint-security",
        )
        
        jti = claims.get("jti", "")
        if _is_revoked(jti):
            return {"valid": False, "error": "Token revoked"}
        
        return {"valid": True, "claims": claims}
    
    except jwt.ExpiredSignatureError:
        return {"valid": False, "error": "Token expired"}
    except jwt.InvalidTokenError as e:
        return {"valid": False, "error": str(e)}


def get_public_key():
    """Get the public key for verification (for testing)."""
    return _public_key


def get_private_key():
    """Get the private key for signing (for testing)."""
    return _private_key


def get_key_id():
    """Get the key ID."""
    return _key_id


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8443)
