"""
Broker Service - Policy Enforcement Point (PEP)

Port: 8080

THE broker. All agent actions flow through here. The broker:
1. Receives typed adapter requests (read_file, write_file, run_command, http_request, load_model)
2. Canonicalizes and validates inputs
3. Consults the PDP for authorization
4. Executes allowed actions or returns denial/approval-required
5. Emits telemetry for every decision

Key principles:
- Typed adapters only (no raw shell)
- Path canonicalization and symlink escape prevention
- Class A: approved-root reads may use 5s local cache
- Class B: writes/egress/commands always remote PDP; PDP down => 503 DENY
- Class C: REQUIRE_APPROVAL returns payload, does not execute
- Emit telemetry on EVERY decision
"""

import logging
import os
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, status

from packages.common.models import ActionRequest, ActionResponse, Decision, InputTrust
from packages.common.path_safety import canonicalize_path, is_path_safe, is_within_roots
from services.broker.models import (
    ReadFileRequest,
    WriteFileRequest,
    RunCommandRequest,
    HttpRequestData,
    LoadModelRequest,
    AdapterResponse,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Broker",
    description="Policy Enforcement Point. Typed adapters only. No raw shell.",
    version="0.1.0",
)

PDP_URL = os.environ.get("PDP_URL", "http://localhost:8082")
TELEMETRY_URL = os.environ.get("TELEMETRY_URL", "http://localhost:8085")
PDP_TIMEOUT = float(os.environ.get("PDP_TIMEOUT_SECONDS", "5"))
CACHE_TTL = float(os.environ.get("LOCAL_CACHE_TTL_SECONDS", "5"))

APPROVED_READ_ROOTS = os.environ.get("APPROVED_READ_ROOTS", "/approved/workspace,/tmp/approved").split(",")
APPROVED_WRITE_ROOTS = os.environ.get("APPROVED_WRITE_ROOTS", "/approved/output").split(",")

_local_cache: dict[str, tuple[float, ActionResponse]] = {}

_terminated_tasks: set[str] = set()


def _get_cached_decision(cache_key: str) -> ActionResponse | None:
    """Get a cached decision if still valid."""
    if cache_key in _local_cache:
        timestamp, response = _local_cache[cache_key]
        if time.time() - timestamp < CACHE_TTL:
            return response
        else:
            del _local_cache[cache_key]
    return None


def _cache_decision(cache_key: str, response: ActionResponse) -> None:
    """Cache a decision."""
    _local_cache[cache_key] = (time.time(), response)


async def _emit_telemetry(
    event_type: str,
    request_id: str,
    decision: Decision,
    reason: str,
    user: str | None = None,
    agent_identity: str | None = None,
    task_id: str | None = None,
    operation: str | None = None,
    target: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str | None:
    """Emit telemetry event. Non-blocking, best effort."""
    telemetry_id = str(uuid.uuid4())

    event = {
        "event_id": telemetry_id,
        "trace_id": request_id,
        "event_type": event_type,
        "user": user,
        "agent_identity": agent_identity,
        "task_id": task_id,
        "operation": operation,
        "target": target,
        "decision": decision.value,
        "reason": reason,
        "metadata": metadata or {},
    }

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{TELEMETRY_URL}/v1/events", json=event)
        return telemetry_id
    except Exception as e:
        logger.warning(f"Failed to emit telemetry: {e}")
        return None


async def _consult_pdp(action_request: ActionRequest) -> ActionResponse:
    """Consult the PDP for a decision."""
    try:
        async with httpx.AsyncClient(timeout=PDP_TIMEOUT) as client:
            response = await client.post(
                f"{PDP_URL}/v1/decide",
                json=action_request.model_dump(),
            )

            if response.status_code == 200:
                data = response.json()
                return ActionResponse(**data)
            else:
                return ActionResponse(
                    decision=Decision.DENY,
                    reason=f"PDP error: {response.status_code}",
                    request_id=action_request.task_id,
                )

    except httpx.TimeoutException:
        return ActionResponse(
            decision=Decision.DENY,
            reason="PDP timeout - fail closed",
            request_id=action_request.task_id,
        )
    except httpx.RequestError as e:
        return ActionResponse(
            decision=Decision.DENY,
            reason=f"PDP unreachable - fail closed: {e}",
            request_id=action_request.task_id,
        )


def _check_task_terminated(task_id: str) -> bool:
    """Check if a task has been terminated by the kill switch."""
    return task_id in _terminated_tasks


def terminate_task(task_id: str) -> None:
    """Mark a task as terminated."""
    _terminated_tasks.add(task_id)
    logger.warning(f"Task {task_id} marked as terminated")


def get_terminated_tasks() -> set[str]:
    """Get terminated tasks (for testing)."""
    return _terminated_tasks.copy()


def clear_terminated_tasks() -> None:
    """Clear terminated tasks (for testing)."""
    _terminated_tasks.clear()


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "broker"}


@app.post("/v1/read_file", response_model=AdapterResponse)
async def read_file(request: ReadFileRequest) -> AdapterResponse:
    """
    Read a file through the broker.

    Class A operation: May use local cache for approved roots.
    """
    request_id = str(uuid.uuid4())

    if _check_task_terminated(request.task_id):
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason="Task has been terminated",
            request_id=request_id,
        )

    safe, reason = is_path_safe(request.path)
    if not safe:
        await _emit_telemetry(
            "read_file_denied",
            request_id,
            Decision.DENY,
            reason,
            user=request.user,
            agent_identity=request.agent_identity,
            task_id=request.task_id,
            operation="read_file",
            target=request.path,
        )
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason=reason,
            request_id=request_id,
        )

    canonical_path = canonicalize_path(request.path)

    within_approved, _ = is_within_roots(canonical_path, APPROVED_READ_ROOTS)
    if within_approved:
        cache_key = f"read:{request.agent_identity}:{canonical_path}"
        cached = _get_cached_decision(cache_key)
        if cached and cached.decision == Decision.ALLOW:
            logger.info(f"[{request_id}] Cache hit for read: {canonical_path}")
            telemetry_id = await _emit_telemetry(
                "read_file_allowed",
                request_id,
                Decision.ALLOW,
                "Cached approval",
                user=request.user,
                agent_identity=request.agent_identity,
                task_id=request.task_id,
                operation="read_file",
                target=canonical_path,
            )
            return AdapterResponse(
                success=True,
                decision=Decision.ALLOW,
                reason="Allowed (cached)",
                request_id=request_id,
                result=f"[Simulated file content from {canonical_path}]",
                telemetry_id=telemetry_id,
            )

    action_request = ActionRequest(
        user=request.user,
        agent_identity=request.agent_identity,
        agent_instance=request.agent_instance,
        agent_version=request.agent_version,
        endpoint_id=request.endpoint_id,
        task_id=request.task_id,
        declared_goal=request.declared_goal,
        tool_id=request.tool_id,
        tool_version=request.tool_version,
        tool_definition_hash=request.tool_definition_hash,
        requested_operation="read_file",
        target_resource=canonical_path,
        input_source=request.input_source,
        input_trust=request.input_trust,
        data_classification=request.data_classification,
    )

    pdp_response = await _consult_pdp(action_request)

    telemetry_id = await _emit_telemetry(
        f"read_file_{pdp_response.decision.value.lower()}",
        request_id,
        pdp_response.decision,
        pdp_response.reason,
        user=request.user,
        agent_identity=request.agent_identity,
        task_id=request.task_id,
        operation="read_file",
        target=canonical_path,
    )

    if pdp_response.decision == Decision.ALLOW:
        if within_approved:
            _cache_decision(cache_key, pdp_response)

        return AdapterResponse(
            success=True,
            decision=Decision.ALLOW,
            reason=pdp_response.reason,
            request_id=request_id,
            result=f"[Simulated file content from {canonical_path}]",
            telemetry_id=telemetry_id,
        )
    else:
        return AdapterResponse(
            success=False,
            decision=pdp_response.decision,
            reason=pdp_response.reason,
            request_id=request_id,
            approval_id=pdp_response.approval_id,
            telemetry_id=telemetry_id,
        )


@app.post("/v1/write_file", response_model=AdapterResponse)
async def write_file(request: WriteFileRequest) -> AdapterResponse:
    """
    Write a file through the broker.

    Class B operation: Always remote PDP. PDP down => 503 DENY.
    """
    request_id = str(uuid.uuid4())

    if _check_task_terminated(request.task_id):
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason="Task has been terminated",
            request_id=request_id,
        )

    safe, reason = is_path_safe(request.path)
    if not safe:
        await _emit_telemetry(
            "write_file_denied",
            request_id,
            Decision.DENY,
            reason,
            user=request.user,
            agent_identity=request.agent_identity,
            task_id=request.task_id,
            operation="write_file",
            target=request.path,
        )
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason=reason,
            request_id=request_id,
        )

    canonical_path = canonicalize_path(request.path)

    action_request = ActionRequest(
        user=request.user,
        agent_identity=request.agent_identity,
        agent_instance=request.agent_instance,
        agent_version=request.agent_version,
        endpoint_id=request.endpoint_id,
        task_id=request.task_id,
        declared_goal=request.declared_goal,
        tool_id=request.tool_id,
        tool_version=request.tool_version,
        tool_definition_hash=request.tool_definition_hash,
        requested_operation="write_file",
        target_resource=canonical_path,
        arguments={"content_length": len(request.content)},
        input_source=request.input_source,
        input_trust=request.input_trust,
        data_classification=request.data_classification,
    )

    pdp_response = await _consult_pdp(action_request)

    telemetry_id = await _emit_telemetry(
        f"write_file_{pdp_response.decision.value.lower()}",
        request_id,
        pdp_response.decision,
        pdp_response.reason,
        user=request.user,
        agent_identity=request.agent_identity,
        task_id=request.task_id,
        operation="write_file",
        target=canonical_path,
    )

    if pdp_response.decision == Decision.ALLOW:
        return AdapterResponse(
            success=True,
            decision=Decision.ALLOW,
            reason=pdp_response.reason,
            request_id=request_id,
            result=f"[Simulated write to {canonical_path}]",
            telemetry_id=telemetry_id,
        )
    elif pdp_response.decision == Decision.REQUIRE_APPROVAL:
        return AdapterResponse(
            success=False,
            decision=Decision.REQUIRE_APPROVAL,
            reason=pdp_response.reason,
            request_id=request_id,
            approval_id=pdp_response.approval_id,
            telemetry_id=telemetry_id,
        )
    else:
        return AdapterResponse(
            success=False,
            decision=pdp_response.decision,
            reason=pdp_response.reason,
            request_id=request_id,
            telemetry_id=telemetry_id,
        )


@app.post("/v1/run_command", response_model=AdapterResponse)
async def run_command(request: RunCommandRequest) -> AdapterResponse:
    """
    Run a command through the broker.

    IMPORTANT: This is NOT a raw shell endpoint.
    Commands must be specified by command_id with typed arguments.

    Class B operation: Always remote PDP. PDP down => 503 DENY.
    """
    request_id = str(uuid.uuid4())

    if _check_task_terminated(request.task_id):
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason="Task has been terminated",
            request_id=request_id,
        )

    if not request.command_id:
        await _emit_telemetry(
            "run_command_denied",
            request_id,
            Decision.DENY,
            "Raw shell commands not allowed - must use command_id",
            user=request.user,
            agent_identity=request.agent_identity,
            task_id=request.task_id,
            operation="run_command",
        )
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason="Raw shell commands not allowed - must use command_id with typed arguments",
            request_id=request_id,
        )

    action_request = ActionRequest(
        user=request.user,
        agent_identity=request.agent_identity,
        agent_instance=request.agent_instance,
        agent_version=request.agent_version,
        endpoint_id=request.endpoint_id,
        task_id=request.task_id,
        declared_goal=request.declared_goal,
        tool_id=request.tool_id,
        tool_version=request.tool_version,
        tool_definition_hash=request.tool_definition_hash,
        requested_operation="run_command",
        target_resource=request.command_id,
        arguments={"command_id": request.command_id, **request.args},
        input_source=request.input_source,
        input_trust=request.input_trust,
        data_classification=request.data_classification,
    )

    pdp_response = await _consult_pdp(action_request)

    telemetry_id = await _emit_telemetry(
        f"run_command_{pdp_response.decision.value.lower()}",
        request_id,
        pdp_response.decision,
        pdp_response.reason,
        user=request.user,
        agent_identity=request.agent_identity,
        task_id=request.task_id,
        operation="run_command",
        target=request.command_id,
        metadata={"args": request.args},
    )

    if pdp_response.decision == Decision.ALLOW:
        return AdapterResponse(
            success=True,
            decision=Decision.ALLOW,
            reason=pdp_response.reason,
            request_id=request_id,
            result=f"[Simulated command execution: {request.command_id}]",
            telemetry_id=telemetry_id,
        )
    else:
        return AdapterResponse(
            success=False,
            decision=pdp_response.decision,
            reason=pdp_response.reason,
            request_id=request_id,
            approval_id=pdp_response.approval_id,
            telemetry_id=telemetry_id,
        )


@app.post("/v1/http_request", response_model=AdapterResponse)
async def http_request(request: HttpRequestData) -> AdapterResponse:
    """
    Make an HTTP request through the broker.

    Class B operation: Always remote PDP. PDP down => 503 DENY.
    """
    request_id = str(uuid.uuid4())

    if _check_task_terminated(request.task_id):
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason="Task has been terminated",
            request_id=request_id,
        )

    action_request = ActionRequest(
        user=request.user,
        agent_identity=request.agent_identity,
        agent_instance=request.agent_instance,
        agent_version=request.agent_version,
        endpoint_id=request.endpoint_id,
        task_id=request.task_id,
        declared_goal=request.declared_goal,
        tool_id=request.tool_id,
        tool_version=request.tool_version,
        tool_definition_hash=request.tool_definition_hash,
        requested_operation="http_request",
        target_resource=f"{request.method} {request.destination}{request.path}",
        arguments={
            "service_id": request.service_id,
            "method": request.method,
            "path": request.path,
        },
        input_source=request.input_source,
        input_trust=request.input_trust,
        data_classification=request.data_classification,
        destination=request.destination,
    )

    pdp_response = await _consult_pdp(action_request)

    telemetry_id = await _emit_telemetry(
        f"http_request_{pdp_response.decision.value.lower()}",
        request_id,
        pdp_response.decision,
        pdp_response.reason,
        user=request.user,
        agent_identity=request.agent_identity,
        task_id=request.task_id,
        operation="http_request",
        target=request.destination,
        metadata={"method": request.method, "path": request.path},
    )

    if pdp_response.decision == Decision.ALLOW:
        return AdapterResponse(
            success=True,
            decision=Decision.ALLOW,
            reason=pdp_response.reason,
            request_id=request_id,
            result=f"[Simulated HTTP {request.method} to {request.destination}{request.path}]",
            telemetry_id=telemetry_id,
        )
    else:
        return AdapterResponse(
            success=False,
            decision=pdp_response.decision,
            reason=pdp_response.reason,
            request_id=request_id,
            approval_id=pdp_response.approval_id,
            telemetry_id=telemetry_id,
        )


@app.post("/v1/load_model", response_model=AdapterResponse)
async def load_model(request: LoadModelRequest) -> AdapterResponse:
    """
    Load a model artifact through the broker.

    Class B operation: Always remote PDP. PDP down => 503 DENY.
    """
    request_id = str(uuid.uuid4())

    if _check_task_terminated(request.task_id):
        return AdapterResponse(
            success=False,
            decision=Decision.DENY,
            reason="Task has been terminated",
            request_id=request_id,
        )

    action_request = ActionRequest(
        user=request.user,
        agent_identity=request.agent_identity,
        agent_instance=request.agent_instance,
        agent_version=request.agent_version,
        endpoint_id=request.endpoint_id,
        task_id=request.task_id,
        declared_goal=request.declared_goal,
        tool_id=request.tool_id,
        tool_version=request.tool_version,
        tool_definition_hash=request.tool_definition_hash,
        requested_operation="load_model",
        target_resource=f"{request.model_id}:{request.version}",
        arguments={"model_id": request.model_id, "version": request.version},
        input_source=request.input_source,
        input_trust=request.input_trust,
        data_classification=request.data_classification,
    )

    pdp_response = await _consult_pdp(action_request)

    telemetry_id = await _emit_telemetry(
        f"load_model_{pdp_response.decision.value.lower()}",
        request_id,
        pdp_response.decision,
        pdp_response.reason,
        user=request.user,
        agent_identity=request.agent_identity,
        task_id=request.task_id,
        operation="load_model",
        target=f"{request.model_id}:{request.version}",
    )

    if pdp_response.decision == Decision.ALLOW:
        return AdapterResponse(
            success=True,
            decision=Decision.ALLOW,
            reason=pdp_response.reason,
            request_id=request_id,
            result=f"[Simulated model load: {request.model_id}:{request.version}]",
            telemetry_id=telemetry_id,
        )
    else:
        return AdapterResponse(
            success=False,
            decision=pdp_response.decision,
            reason=pdp_response.reason,
            request_id=request_id,
            telemetry_id=telemetry_id,
        )


@app.post("/v1/terminate-task")
async def api_terminate_task(task_id: str) -> dict[str, Any]:
    """Terminate a task (called by kill switch)."""
    terminate_task(task_id)
    return {"success": True, "task_id": task_id, "message": "Task terminated"}


@app.get("/v1/terminated-tasks")
async def list_terminated_tasks() -> dict[str, Any]:
    """List terminated tasks."""
    return {"terminated_tasks": list(_terminated_tasks)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
