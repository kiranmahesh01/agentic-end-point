"""
Kill Switch Service

Port: 8086

Emergency termination service for agents. This is the hard stop.

The kill switch does NOT send a polite stop to the agent.
It revokes tokens, suspends the component, terminates tasks,
and hooks EDR isolate + egress deny.

Order of operations:
1. Registry: suspend component
2. Identity: revoke all tokens for agent
3. Broker: terminate task IDs
4. Log EDR isolate hook (simulated)
5. Log egress deny hook (simulated)
"""

import logging
import os
import uuid
from datetime import datetime
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, status

from services.killswitch.models import KillRequest, KillStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Kill Switch",
    description="Emergency agent termination. Revokes, suspends, terminates.",
    version="0.1.0",
)

REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://localhost:8081")
IDENTITY_URL = os.environ.get("IDENTITY_URL", "http://localhost:8083")
BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8080")
TELEMETRY_URL = os.environ.get("TELEMETRY_URL", "http://localhost:8085")

_kill_history: dict[str, KillStatus] = {}


async def _suspend_in_registry(agent_id: str, reason: str) -> tuple[bool, str]:
    """Suspend the agent in the registry."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{REGISTRY_URL}/v1/components/{agent_id}/suspend",
                params={"reason": reason},
            )

            if response.status_code == 200:
                return True, "Component suspended"
            elif response.status_code == 404:
                return False, f"Component not found: {agent_id}"
            else:
                return False, f"Registry error: {response.status_code}"

    except httpx.RequestError as e:
        return False, f"Registry unreachable: {e}"


async def _revoke_tokens(agent_id: str, reason: str) -> tuple[bool, int, str]:
    """Revoke all tokens for the agent."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{IDENTITY_URL}/v1/revoke-agent",
                params={"agent_identity": agent_id, "reason": reason},
            )

            if response.status_code == 200:
                data = response.json()
                return True, data.get("tokens_revoked", 0), "Tokens revoked"
            else:
                return False, 0, f"Identity error: {response.status_code}"

    except httpx.RequestError as e:
        return False, 0, f"Identity unreachable: {e}"


async def _terminate_tasks(task_ids: list[str]) -> tuple[list[str], list[str]]:
    """Terminate tasks in the broker."""
    terminated = []
    errors = []

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            for task_id in task_ids:
                try:
                    response = await client.post(
                        f"{BROKER_URL}/v1/terminate-task",
                        params={"task_id": task_id},
                    )

                    if response.status_code == 200:
                        terminated.append(task_id)
                    else:
                        errors.append(f"Failed to terminate {task_id}: {response.status_code}")

                except httpx.RequestError as e:
                    errors.append(f"Failed to terminate {task_id}: {e}")

    except Exception as e:
        errors.append(f"Broker unreachable: {e}")

    return terminated, errors


async def _log_edr_isolate(agent_id: str, reason: str) -> bool:
    """
    Log EDR isolate hook.

    In production, this would call the EDR API to isolate the endpoint.
    Here we just log it as a simulated action.
    """
    logger.warning(f"EDR ISOLATE HOOK: Agent {agent_id} - {reason}")
    return True


async def _log_egress_deny(agent_id: str, reason: str) -> bool:
    """
    Log egress deny hook.

    In production, this would update firewall rules to deny egress.
    Here we just log it as a simulated action.
    """
    logger.warning(f"EGRESS DENY HOOK: Agent {agent_id} - {reason}")
    return True


async def _emit_kill_telemetry(kill_status: KillStatus) -> None:
    """Emit telemetry for kill switch activation."""
    event = {
        "event_id": str(uuid.uuid4()),
        "trace_id": kill_status.kill_id,
        "event_type": "kill_switch_activated",
        "agent_identity": kill_status.agent_id,
        "operation": "kill_switch",
        "decision": "TERMINATE_AND_REVOKE",
        "reason": kill_status.reason,
        "metadata": {
            "initiated_by": kill_status.initiated_by,
            "registry_suspended": kill_status.registry_suspended,
            "tokens_revoked": kill_status.tokens_revoked,
            "tasks_terminated": kill_status.tasks_terminated,
            "edr_isolate_logged": kill_status.edr_isolate_logged,
            "egress_deny_logged": kill_status.egress_deny_logged,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{TELEMETRY_URL}/v1/events", json=event)
    except Exception as e:
        logger.warning(f"Failed to emit kill telemetry: {e}")


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "killswitch"}


@app.post("/v1/kill", response_model=KillStatus)
async def kill(request: KillRequest) -> KillStatus:
    """
    Activate kill switch for an agent.

    This is the nuclear option. It:
    1. Suspends the component in the registry
    2. Revokes all tokens for the agent
    3. Terminates active tasks
    4. Logs EDR isolate hook
    5. Logs egress deny hook
    """
    kill_id = f"kill-{uuid.uuid4().hex[:12]}"
    timestamp = datetime.utcnow()
    errors = []

    logger.warning(
        f"KILL SWITCH ACTIVATED: {kill_id} for {request.agent_id} "
        f"by {request.initiated_by}: {request.reason}"
    )

    registry_ok, registry_msg = await _suspend_in_registry(
        request.agent_id, request.reason
    )
    if not registry_ok:
        errors.append(f"Registry: {registry_msg}")

    tokens_ok, tokens_count, tokens_msg = await _revoke_tokens(
        request.agent_id, request.reason
    )
    if not tokens_ok:
        errors.append(f"Identity: {tokens_msg}")

    terminated_tasks, task_errors = await _terminate_tasks(request.task_ids)
    errors.extend(task_errors)

    edr_logged = await _log_edr_isolate(request.agent_id, request.reason)
    egress_logged = await _log_egress_deny(request.agent_id, request.reason)

    kill_status = KillStatus(
        kill_id=kill_id,
        agent_id=request.agent_id,
        status="completed" if not errors else "completed_with_errors",
        initiated_by=request.initiated_by,
        reason=request.reason,
        timestamp=timestamp,
        registry_suspended=registry_ok,
        tokens_revoked=tokens_count,
        tasks_terminated=terminated_tasks,
        edr_isolate_logged=edr_logged,
        egress_deny_logged=egress_logged,
        errors=errors,
    )

    _kill_history[kill_id] = kill_status

    await _emit_kill_telemetry(kill_status)

    logger.info(
        f"Kill switch {kill_id} completed: "
        f"suspended={registry_ok}, tokens_revoked={tokens_count}, "
        f"tasks_terminated={len(terminated_tasks)}, errors={len(errors)}"
    )

    return kill_status


@app.get("/v1/status/{kill_id}", response_model=KillStatus)
async def get_kill_status(kill_id: str) -> KillStatus:
    """Get the status of a kill switch activation."""
    if kill_id not in _kill_history:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Kill switch activation not found",
        )

    return _kill_history[kill_id]


@app.get("/v1/status")
async def list_kill_history(
    agent_id: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """List kill switch history."""
    history = list(_kill_history.values())

    if agent_id:
        history = [k for k in history if k.agent_id == agent_id]

    history = sorted(history, key=lambda k: k.timestamp, reverse=True)[:limit]

    return {
        "count": len(history),
        "kills": [k.model_dump() for k in history],
    }


@app.delete("/v1/history")
async def clear_history() -> dict[str, str]:
    """Clear kill history (for testing only)."""
    _kill_history.clear()
    return {"message": "Kill history cleared"}


def get_kill_history() -> dict[str, KillStatus]:
    """Get kill history (for testing)."""
    return _kill_history


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8086)
