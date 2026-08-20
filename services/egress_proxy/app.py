"""
Egress Proxy Service

Port: 8087

A real egress proxy that enforces default-deny networking.
All outbound HTTP requests from agents must go through this proxy.

Key features:
- Default deny: only allowlisted destinations permitted
- Per-agent deny rules: kill switch can block specific agents
- Real enforcement: blocked requests return 403, not just logged
- Health check endpoints always allowed
"""

import logging
import os
import re
from datetime import datetime
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, status, Request, Response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Egress Proxy",
    description="Real egress proxy with default-deny enforcement.",
    version="0.1.0",
)

REDIS_URL = os.environ.get("REDIS_URL", "")

DEFAULT_ALLOWLIST = set(
    os.environ.get("EGRESS_ALLOWLIST", "reports.internal.example").split(",")
)

ALWAYS_ALLOWED = {
    "localhost",
    "127.0.0.1",
    "registry",
    "pdp",
    "identity",
    "broker",
    "approval",
    "telemetry",
    "killswitch",
    "idp",
    "egress-proxy",
    "edr-sensor",
    "redis",
    "lb",
}

_allowlist: set[str] = DEFAULT_ALLOWLIST.copy()
_blocked_agents: set[str] = set()
_deny_log: list[dict[str, Any]] = []

try:
    import redis
    _redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None
except ImportError:
    _redis_client = None


def _is_agent_blocked(agent_id: str) -> bool:
    """Check if an agent is blocked from egress."""
    if _redis_client:
        try:
            return _redis_client.sismember("blocked_agents", agent_id)
        except Exception:
            pass
    return agent_id in _blocked_agents


def _block_agent(agent_id: str) -> None:
    """Block an agent from egress."""
    if _redis_client:
        try:
            _redis_client.sadd("blocked_agents", agent_id)
            return
        except Exception:
            pass
    _blocked_agents.add(agent_id)


def _unblock_agent(agent_id: str) -> None:
    """Unblock an agent."""
    if _redis_client:
        try:
            _redis_client.srem("blocked_agents", agent_id)
            return
        except Exception:
            pass
    _blocked_agents.discard(agent_id)


def _is_allowed(destination: str) -> bool:
    """Check if a destination is in the allowlist."""
    destination = destination.lower().strip()
    
    if destination in ALWAYS_ALLOWED:
        return True
    
    host = destination.split(":")[0]
    
    if host in _allowlist:
        return True
    
    for allowed in _allowlist:
        if host.endswith(f".{allowed}"):
            return True
    
    return False


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "egress-proxy"}


@app.post("/v1/proxy")
async def proxy_request(
    request: Request,
) -> Response:
    """
    Proxy an HTTP request to an external destination.
    
    Request body should be JSON with:
    - destination: target host/URL
    - method: HTTP method
    - path: URL path
    - headers: optional headers
    - body: optional body
    - agent_id: requesting agent identity
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON body"
        )
    
    destination = data.get("destination", "")
    method = data.get("method", "GET").upper()
    path = data.get("path", "/")
    headers = data.get("headers", {})
    body = data.get("body")
    agent_id = data.get("agent_id", "unknown")
    
    if _is_agent_blocked(agent_id):
        _deny_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": agent_id,
            "destination": destination,
            "reason": "Agent blocked by kill switch",
        })
        logger.warning(f"EGRESS DENIED: Agent {agent_id} is blocked")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Egress denied: agent {agent_id} is blocked"
        )
    
    if not _is_allowed(destination):
        _deny_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": agent_id,
            "destination": destination,
            "reason": "Destination not in allowlist",
        })
        logger.warning(f"EGRESS DENIED: {destination} not in allowlist")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Egress denied: {destination} not in allowlist"
        )
    
    url = f"https://{destination}{path}" if not destination.startswith("http") else f"{destination}{path}"
    
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )
            
            logger.info(f"EGRESS ALLOWED: {method} {destination}{path} -> {response.status_code}")
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
            )
    
    except httpx.RequestError as e:
        logger.error(f"EGRESS ERROR: {destination} - {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to reach destination: {e}"
        )


@app.get("/v1/check")
async def check_destination(destination: str, agent_id: str = "unknown") -> dict[str, Any]:
    """Check if a destination would be allowed."""
    if _is_agent_blocked(agent_id):
        return {
            "allowed": False,
            "destination": destination,
            "reason": "Agent blocked by kill switch",
        }
    
    allowed = _is_allowed(destination)
    return {
        "allowed": allowed,
        "destination": destination,
        "reason": "In allowlist" if allowed else "Not in allowlist",
    }


@app.post("/v1/block-agent")
async def block_agent(agent_id: str, reason: str = "Kill switch") -> dict[str, Any]:
    """
    Block an agent from all egress.
    
    Called by kill switch to immediately deny network access.
    """
    _block_agent(agent_id)
    logger.warning(f"EGRESS BLOCK: Agent {agent_id} blocked - {reason}")
    
    return {
        "success": True,
        "agent_id": agent_id,
        "blocked": True,
        "reason": reason,
    }


@app.post("/v1/unblock-agent")
async def unblock_agent(agent_id: str) -> dict[str, Any]:
    """Unblock an agent."""
    _unblock_agent(agent_id)
    logger.info(f"EGRESS UNBLOCK: Agent {agent_id}")
    
    return {
        "success": True,
        "agent_id": agent_id,
        "blocked": False,
    }


@app.get("/v1/allowlist")
async def get_allowlist() -> dict[str, Any]:
    """Get current allowlist."""
    return {
        "allowlist": list(_allowlist),
        "always_allowed": list(ALWAYS_ALLOWED),
    }


@app.post("/v1/allowlist")
async def add_to_allowlist(destination: str) -> dict[str, Any]:
    """Add a destination to the allowlist."""
    _allowlist.add(destination.lower().strip())
    logger.info(f"ALLOWLIST ADD: {destination}")
    return {"added": destination, "allowlist": list(_allowlist)}


@app.delete("/v1/allowlist")
async def remove_from_allowlist(destination: str) -> dict[str, Any]:
    """Remove a destination from the allowlist."""
    _allowlist.discard(destination.lower().strip())
    logger.info(f"ALLOWLIST REMOVE: {destination}")
    return {"removed": destination, "allowlist": list(_allowlist)}


@app.get("/v1/blocked-agents")
async def get_blocked_agents() -> dict[str, Any]:
    """Get list of blocked agents."""
    if _redis_client:
        try:
            agents = _redis_client.smembers("blocked_agents")
            return {"blocked_agents": [a.decode() for a in agents]}
        except Exception:
            pass
    return {"blocked_agents": list(_blocked_agents)}


@app.get("/v1/deny-log")
async def get_deny_log(limit: int = 100) -> dict[str, Any]:
    """Get recent deny log entries."""
    return {
        "count": len(_deny_log),
        "entries": _deny_log[-limit:],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8087)
