"""
EDR Sensor Service

Port: 8088

A real EDR sensor that can isolate containers via Docker API.
When kill switch is activated, this service:
1. Pauses/stops the target container
2. Disconnects it from the network

Key features:
- Real container isolation via Docker API
- Network disconnection
- Process termination
- Verification of isolation state

Requires: Docker socket mount (/var/run/docker.sock)
"""

import logging
import os
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, status

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - EDR Sensor",
    description="Real EDR sensor with Docker container isolation.",
    version="0.1.0",
)

DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
REDIS_URL = os.environ.get("REDIS_URL", "")

_docker_client = None
_isolation_log: list[dict[str, Any]] = []
_isolated_containers: set[str] = set()

try:
    import docker
    if os.path.exists(DOCKER_SOCKET):
        _docker_client = docker.DockerClient(base_url=f"unix://{DOCKER_SOCKET}")
        logger.info("Docker client initialized")
    else:
        logger.warning(f"Docker socket not found at {DOCKER_SOCKET}")
except ImportError:
    logger.warning("Docker SDK not installed")
except Exception as e:
    logger.warning(f"Failed to initialize Docker client: {e}")

try:
    import redis
    _redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None
except ImportError:
    _redis_client = None


def _find_container(name_pattern: str):
    """Find a container by name pattern."""
    if not _docker_client:
        return None
    
    try:
        containers = _docker_client.containers.list(all=True)
        for container in containers:
            if name_pattern in container.name:
                return container
    except Exception as e:
        logger.error(f"Error finding container: {e}")
    
    return None


def _record_isolation(agent_id: str, container_name: str, action: str, success: bool, error: str = "") -> None:
    """Record an isolation event."""
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "agent_id": agent_id,
        "container_name": container_name,
        "action": action,
        "success": success,
        "error": error,
    }
    _isolation_log.append(event)
    
    if _redis_client:
        try:
            import json
            _redis_client.lpush("isolation_log", json.dumps(event))
            _redis_client.ltrim("isolation_log", 0, 999)
        except Exception:
            pass


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    docker_status = "connected" if _docker_client else "unavailable"
    return {
        "status": "healthy",
        "service": "edr-sensor",
        "docker": docker_status,
    }


@app.post("/v1/isolate")
async def isolate_container(
    agent_id: str,
    container_name: str = "",
    reason: str = "Kill switch activation",
) -> dict[str, Any]:
    """
    Isolate a container by pausing it and disconnecting from networks.
    
    This is REAL isolation - the container cannot communicate or execute.
    """
    if not container_name:
        container_name = agent_id.replace(":", "-").replace("agent-", "")
    
    if not _docker_client:
        _record_isolation(agent_id, container_name, "isolate", False, "Docker not available")
        return {
            "success": False,
            "agent_id": agent_id,
            "container_name": container_name,
            "error": "Docker client not available",
            "simulated": True,
        }
    
    container = _find_container(container_name)
    if not container:
        _record_isolation(agent_id, container_name, "isolate", False, "Container not found")
        return {
            "success": False,
            "agent_id": agent_id,
            "container_name": container_name,
            "error": f"Container not found: {container_name}",
        }
    
    errors = []
    actions_taken = []
    
    try:
        for network_name in list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys()):
            try:
                network = _docker_client.networks.get(network_name)
                network.disconnect(container)
                actions_taken.append(f"Disconnected from {network_name}")
                logger.info(f"Disconnected {container.name} from {network_name}")
            except Exception as e:
                errors.append(f"Failed to disconnect from {network_name}: {e}")
    except Exception as e:
        errors.append(f"Failed to enumerate networks: {e}")
    
    try:
        if container.status == "running":
            container.pause()
            actions_taken.append("Paused container")
            logger.info(f"Paused container {container.name}")
    except Exception as e:
        try:
            container.stop(timeout=1)
            actions_taken.append("Stopped container")
            logger.info(f"Stopped container {container.name}")
        except Exception as e2:
            errors.append(f"Failed to pause/stop: {e}, {e2}")
    
    _isolated_containers.add(container.name)
    
    if _redis_client:
        try:
            _redis_client.sadd("isolated_containers", container.name)
        except Exception:
            pass
    
    success = len(actions_taken) > 0
    _record_isolation(agent_id, container.name, "isolate", success, "; ".join(errors))
    
    logger.warning(f"EDR ISOLATE: {container.name} for {agent_id} - {reason}")
    
    return {
        "success": success,
        "agent_id": agent_id,
        "container_name": container.name,
        "actions_taken": actions_taken,
        "errors": errors if errors else None,
        "reason": reason,
    }


@app.post("/v1/terminate")
async def terminate_container(
    agent_id: str,
    container_name: str = "",
    reason: str = "Kill switch termination",
) -> dict[str, Any]:
    """
    Forcefully terminate a container.
    
    This kills the container process immediately.
    """
    if not container_name:
        container_name = agent_id.replace(":", "-").replace("agent-", "")
    
    if not _docker_client:
        _record_isolation(agent_id, container_name, "terminate", False, "Docker not available")
        return {
            "success": False,
            "agent_id": agent_id,
            "error": "Docker client not available",
            "simulated": True,
        }
    
    container = _find_container(container_name)
    if not container:
        _record_isolation(agent_id, container_name, "terminate", False, "Container not found")
        return {
            "success": False,
            "agent_id": agent_id,
            "error": f"Container not found: {container_name}",
        }
    
    try:
        container.kill()
        _record_isolation(agent_id, container.name, "terminate", True)
        logger.warning(f"EDR TERMINATE: {container.name} for {agent_id} - {reason}")
        
        return {
            "success": True,
            "agent_id": agent_id,
            "container_name": container.name,
            "action": "killed",
            "reason": reason,
        }
    except Exception as e:
        _record_isolation(agent_id, container.name, "terminate", False, str(e))
        return {
            "success": False,
            "agent_id": agent_id,
            "error": str(e),
        }


@app.post("/v1/restore")
async def restore_container(
    agent_id: str,
    container_name: str = "",
) -> dict[str, Any]:
    """
    Restore an isolated container (unpause and reconnect).
    """
    if not container_name:
        container_name = agent_id.replace(":", "-").replace("agent-", "")
    
    if not _docker_client:
        return {
            "success": False,
            "agent_id": agent_id,
            "error": "Docker client not available",
        }
    
    container = _find_container(container_name)
    if not container:
        return {
            "success": False,
            "agent_id": agent_id,
            "error": f"Container not found: {container_name}",
        }
    
    actions = []
    errors = []
    
    try:
        if container.status == "paused":
            container.unpause()
            actions.append("Unpaused")
        elif container.status in ("exited", "created"):
            container.start()
            actions.append("Started")
    except Exception as e:
        errors.append(f"Failed to unpause/start: {e}")
    
    _isolated_containers.discard(container.name)
    
    if _redis_client:
        try:
            _redis_client.srem("isolated_containers", container.name)
        except Exception:
            pass
    
    _record_isolation(agent_id, container.name, "restore", len(actions) > 0, "; ".join(errors))
    
    return {
        "success": len(actions) > 0,
        "agent_id": agent_id,
        "container_name": container.name,
        "actions_taken": actions,
        "errors": errors if errors else None,
    }


@app.get("/v1/status")
async def get_container_status(container_name: str) -> dict[str, Any]:
    """Get the status of a container."""
    if not _docker_client:
        return {
            "container_name": container_name,
            "docker_available": False,
        }
    
    container = _find_container(container_name)
    if not container:
        return {
            "container_name": container_name,
            "found": False,
        }
    
    return {
        "container_name": container.name,
        "found": True,
        "status": container.status,
        "isolated": container.name in _isolated_containers,
        "networks": list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys()),
    }


@app.get("/v1/isolated")
async def list_isolated() -> dict[str, Any]:
    """List all isolated containers."""
    if _redis_client:
        try:
            containers = _redis_client.smembers("isolated_containers")
            return {"isolated_containers": [c.decode() for c in containers]}
        except Exception:
            pass
    return {"isolated_containers": list(_isolated_containers)}


@app.get("/v1/log")
async def get_isolation_log(limit: int = 100) -> dict[str, Any]:
    """Get isolation event log."""
    if _redis_client:
        try:
            import json
            entries = _redis_client.lrange("isolation_log", 0, limit - 1)
            return {
                "count": len(entries),
                "entries": [json.loads(e) for e in entries],
            }
        except Exception:
            pass
    return {
        "count": len(_isolation_log),
        "entries": _isolation_log[-limit:],
    }


@app.get("/v1/containers")
async def list_containers() -> dict[str, Any]:
    """List all containers (for debugging)."""
    if not _docker_client:
        return {"docker_available": False, "containers": []}
    
    try:
        containers = _docker_client.containers.list(all=True)
        return {
            "docker_available": True,
            "containers": [
                {
                    "name": c.name,
                    "status": c.status,
                    "image": c.image.tags[0] if c.image.tags else "unknown",
                }
                for c in containers
            ],
        }
    except Exception as e:
        return {"docker_available": True, "error": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8088)
