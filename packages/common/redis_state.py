"""Redis-backed shared state for HA deployments."""

import json
import logging
import os
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "")

_redis_client = None

try:
    import redis
    if REDIS_URL:
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info(f"Redis client initialized: {REDIS_URL}")
except ImportError:
    logger.warning("Redis not installed, using in-memory storage")
except Exception as e:
    logger.warning(f"Failed to connect to Redis: {e}")


def is_redis_available() -> bool:
    """Check if Redis is available."""
    if not _redis_client:
        return False
    try:
        _redis_client.ping()
        return True
    except Exception:
        return False


class RevocationStore:
    """Shared revocation list storage."""
    
    _local_revoked: set[str] = set()
    
    @classmethod
    def revoke(cls, jti: str, ttl_seconds: int = 300) -> None:
        """Add a JTI to the revocation list."""
        if _redis_client:
            try:
                _redis_client.setex(f"revoked:{jti}", ttl_seconds, "1")
                return
            except Exception as e:
                logger.warning(f"Redis revoke failed: {e}")
        cls._local_revoked.add(jti)
    
    @classmethod
    def is_revoked(cls, jti: str) -> bool:
        """Check if a JTI is revoked."""
        if _redis_client:
            try:
                return _redis_client.exists(f"revoked:{jti}") > 0
            except Exception as e:
                logger.warning(f"Redis check failed: {e}")
        return jti in cls._local_revoked
    
    @classmethod
    def revoke_all_for_agent(cls, agent_id: str, reason: str = "") -> int:
        """Revoke all tokens for an agent."""
        if _redis_client:
            try:
                key = f"agent_revoked:{agent_id}"
                _redis_client.setex(key, 300, reason or "revoked")
                return 1
            except Exception as e:
                logger.warning(f"Redis agent revoke failed: {e}")
        return 0
    
    @classmethod
    def is_agent_revoked(cls, agent_id: str) -> bool:
        """Check if all tokens for an agent are revoked."""
        if _redis_client:
            try:
                return _redis_client.exists(f"agent_revoked:{agent_id}") > 0
            except Exception:
                pass
        return False


class ApprovalStore:
    """Shared approval queue storage."""
    
    _local_approvals: dict[str, dict[str, Any]] = {}
    
    @classmethod
    def create(cls, approval_id: str, data: dict[str, Any]) -> None:
        """Create an approval request."""
        if _redis_client:
            try:
                _redis_client.hset("approvals", approval_id, json.dumps(data))
                return
            except Exception as e:
                logger.warning(f"Redis approval create failed: {e}")
        cls._local_approvals[approval_id] = data
    
    @classmethod
    def get(cls, approval_id: str) -> Optional[dict[str, Any]]:
        """Get an approval request."""
        if _redis_client:
            try:
                data = _redis_client.hget("approvals", approval_id)
                if data:
                    return json.loads(data)
                return None
            except Exception as e:
                logger.warning(f"Redis approval get failed: {e}")
        return cls._local_approvals.get(approval_id)
    
    @classmethod
    def update(cls, approval_id: str, data: dict[str, Any]) -> None:
        """Update an approval request."""
        if _redis_client:
            try:
                _redis_client.hset("approvals", approval_id, json.dumps(data))
                return
            except Exception as e:
                logger.warning(f"Redis approval update failed: {e}")
        cls._local_approvals[approval_id] = data
    
    @classmethod
    def list_all(cls) -> dict[str, dict[str, Any]]:
        """List all approvals."""
        if _redis_client:
            try:
                data = _redis_client.hgetall("approvals")
                return {k: json.loads(v) for k, v in data.items()}
            except Exception as e:
                logger.warning(f"Redis approval list failed: {e}")
        return cls._local_approvals.copy()


class KillStateStore:
    """Shared kill switch state storage."""
    
    _local_kills: dict[str, dict[str, Any]] = {}
    _local_killed_agents: set[str] = set()
    
    @classmethod
    def record_kill(cls, kill_id: str, data: dict[str, Any]) -> None:
        """Record a kill switch activation."""
        agent_id = data.get("agent_id", "")
        
        if _redis_client:
            try:
                _redis_client.hset("kills", kill_id, json.dumps(data))
                if agent_id:
                    _redis_client.sadd("killed_agents", agent_id)
                return
            except Exception as e:
                logger.warning(f"Redis kill record failed: {e}")
        
        cls._local_kills[kill_id] = data
        if agent_id:
            cls._local_killed_agents.add(agent_id)
    
    @classmethod
    def is_agent_killed(cls, agent_id: str) -> bool:
        """Check if an agent has been killed."""
        if _redis_client:
            try:
                return _redis_client.sismember("killed_agents", agent_id)
            except Exception:
                pass
        return agent_id in cls._local_killed_agents
    
    @classmethod
    def get_kill(cls, kill_id: str) -> Optional[dict[str, Any]]:
        """Get a kill record."""
        if _redis_client:
            try:
                data = _redis_client.hget("kills", kill_id)
                if data:
                    return json.loads(data)
                return None
            except Exception:
                pass
        return cls._local_kills.get(kill_id)
    
    @classmethod
    def list_kills(cls) -> list[dict[str, Any]]:
        """List all kills."""
        if _redis_client:
            try:
                data = _redis_client.hgetall("kills")
                return [json.loads(v) for v in data.values()]
            except Exception:
                pass
        return list(cls._local_kills.values())


class PolicyCache:
    """Local policy cache for offline/Class D mode."""
    
    _cache: dict[str, tuple[Any, float]] = {}
    _default_ttl: float = 5.0
    
    @classmethod
    def set(cls, key: str, value: Any, ttl: float = None) -> None:
        """Cache a policy decision."""
        ttl = ttl or cls._default_ttl
        import time
        cls._cache[key] = (value, time.time() + ttl)
    
    @classmethod
    def get(cls, key: str) -> Optional[Any]:
        """Get a cached policy decision."""
        import time
        if key in cls._cache:
            value, expiry = cls._cache[key]
            if time.time() < expiry:
                return value
            del cls._cache[key]
        return None
    
    @classmethod
    def clear(cls) -> None:
        """Clear the cache."""
        cls._cache.clear()
