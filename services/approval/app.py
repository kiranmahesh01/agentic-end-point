"""
Approval Service

Port: 8084

Out-of-band approval service for actions that require human authorization.
This is NOT in-agent UI - approvals happen through a separate channel.

Key principles:
- Signed approval_id (HMAC)
- Required display: user, agent, version, endpoint, task, action, resource, classification, destination, diff
- Degraded mode: queue requests, never auto-approve
- In-agent UI never counts as approval
"""

import hashlib
import hmac
import logging
import os
import uuid
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, status

from packages.common.models import ApprovalRecord, ApprovalStatus
from services.approval.models import ApprovalCreate, ApprovalDecision, ApprovalResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Approval",
    description="Out-of-band approval service. Degraded = queue, never auto-approve.",
    version="0.1.0",
)

HMAC_SECRET = os.environ.get("APPROVAL_HMAC_SECRET", "dev-hmac-secret-change-in-production")

_approvals: dict[str, ApprovalRecord] = {}

_degraded_mode = False


def _generate_approval_id(data: str) -> str:
    """Generate an HMAC-signed approval ID."""
    raw_id = str(uuid.uuid4())
    signature = hmac.new(
        HMAC_SECRET.encode(),
        f"{raw_id}:{data}".encode(),
        hashlib.sha256,
    ).hexdigest()[:12]
    return f"apr-{raw_id[:8]}-{signature}"


def _verify_approval_id(approval_id: str) -> bool:
    """Verify that an approval ID is valid (basic format check)."""
    if not approval_id.startswith("apr-"):
        return False
    parts = approval_id.split("-")
    return len(parts) == 3


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {
        "status": "healthy" if not _degraded_mode else "degraded",
        "service": "approval",
    }


@app.post("/v1/approvals", response_model=ApprovalResponse, status_code=status.HTTP_201_CREATED)
async def create_approval(request: ApprovalCreate) -> ApprovalResponse:
    """
    Create a new approval request.

    Returns an approval_id that must be presented when the action is retried.
    """
    approval_id = _generate_approval_id(f"{request.user}:{request.task_id}")

    record = ApprovalRecord(
        approval_id=approval_id,
        user=request.user,
        agent_identity=request.agent_identity,
        agent_version=request.agent_version,
        endpoint_id=request.endpoint_id,
        task_id=request.task_id,
        requested_operation=request.requested_operation,
        target_resource=request.target_resource,
        data_classification=request.data_classification,
        destination=request.destination,
        diff=request.diff,
        status=ApprovalStatus.PENDING,
        created_at=datetime.utcnow(),
    )

    _approvals[approval_id] = record

    logger.info(
        f"Created approval request {approval_id}: "
        f"{request.requested_operation} on {request.target_resource} "
        f"by {request.agent_identity}"
    )

    return ApprovalResponse(
        approval_id=approval_id,
        status=record.status,
        user=record.user,
        agent_identity=record.agent_identity,
        agent_version=record.agent_version,
        endpoint_id=record.endpoint_id,
        task_id=record.task_id,
        requested_operation=record.requested_operation,
        target_resource=record.target_resource,
        data_classification=record.data_classification,
        destination=record.destination,
        diff=record.diff,
        created_at=record.created_at,
        decided_at=record.decided_at,
        decided_by=record.decided_by,
        reason=record.reason,
    )


@app.get("/v1/approvals/{approval_id}", response_model=ApprovalResponse)
async def get_approval(approval_id: str) -> ApprovalResponse:
    """Get the status of an approval request."""
    if not _verify_approval_id(approval_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid approval ID format",
        )

    record = _approvals.get(approval_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval not found",
        )

    return ApprovalResponse(
        approval_id=approval_id,
        status=record.status,
        user=record.user,
        agent_identity=record.agent_identity,
        agent_version=record.agent_version,
        endpoint_id=record.endpoint_id,
        task_id=record.task_id,
        requested_operation=record.requested_operation,
        target_resource=record.target_resource,
        data_classification=record.data_classification,
        destination=record.destination,
        diff=record.diff,
        created_at=record.created_at,
        decided_at=record.decided_at,
        decided_by=record.decided_by,
        reason=record.reason,
    )


@app.post("/v1/approvals/{approval_id}/decide", response_model=ApprovalResponse)
async def decide_approval(approval_id: str, decision: ApprovalDecision) -> ApprovalResponse:
    """
    Decide on an approval request.

    This endpoint would be called by an out-of-band approval system
    (e.g., Slack bot, email approval, security dashboard).

    IMPORTANT: In-agent UI prompts do NOT count as approval.
    """
    if not _verify_approval_id(approval_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid approval ID format",
        )

    record = _approvals.get(approval_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval not found",
        )

    if record.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval already decided: {record.status.value}",
        )

    if _degraded_mode:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Approval service is degraded - decisions are queued",
        )

    record.status = ApprovalStatus.APPROVED if decision.approved else ApprovalStatus.DENIED
    record.decided_at = datetime.utcnow()
    record.decided_by = decision.decided_by
    record.reason = decision.reason

    _approvals[approval_id] = record

    logger.info(
        f"Approval {approval_id} decided: {record.status.value} "
        f"by {decision.decided_by}: {decision.reason}"
    )

    return ApprovalResponse(
        approval_id=approval_id,
        status=record.status,
        user=record.user,
        agent_identity=record.agent_identity,
        agent_version=record.agent_version,
        endpoint_id=record.endpoint_id,
        task_id=record.task_id,
        requested_operation=record.requested_operation,
        target_resource=record.target_resource,
        data_classification=record.data_classification,
        destination=record.destination,
        diff=record.diff,
        created_at=record.created_at,
        decided_at=record.decided_at,
        decided_by=record.decided_by,
        reason=record.reason,
    )


@app.get("/v1/approvals")
async def list_approvals(
    status_filter: str | None = None,
    user: str | None = None,
    agent_identity: str | None = None,
) -> dict[str, Any]:
    """List approval requests with optional filters."""
    records = list(_approvals.values())

    if status_filter:
        try:
            filter_status = ApprovalStatus(status_filter)
            records = [r for r in records if r.status == filter_status]
        except ValueError:
            pass

    if user:
        records = [r for r in records if r.user == user]

    if agent_identity:
        records = [r for r in records if r.agent_identity == agent_identity]

    return {
        "count": len(records),
        "approvals": [
            ApprovalResponse(
                approval_id=r.approval_id,
                status=r.status,
                user=r.user,
                agent_identity=r.agent_identity,
                agent_version=r.agent_version,
                endpoint_id=r.endpoint_id,
                task_id=r.task_id,
                requested_operation=r.requested_operation,
                target_resource=r.target_resource,
                data_classification=r.data_classification,
                destination=r.destination,
                diff=r.diff,
                created_at=r.created_at,
                decided_at=r.decided_at,
                decided_by=r.decided_by,
                reason=r.reason,
            ).model_dump()
            for r in records
        ],
    }


@app.post("/v1/degraded")
async def set_degraded_mode(enabled: bool) -> dict[str, Any]:
    """Set degraded mode (for testing failure scenarios)."""
    global _degraded_mode
    _degraded_mode = enabled
    logger.warning(f"Degraded mode {'enabled' if enabled else 'disabled'}")
    return {"degraded_mode": _degraded_mode}


@app.delete("/v1/approvals")
async def clear_approvals() -> dict[str, str]:
    """Clear all approvals (for testing only)."""
    _approvals.clear()
    return {"message": "All approvals cleared"}


def get_approvals_store() -> dict[str, ApprovalRecord]:
    """Get approvals store (for testing)."""
    return _approvals


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8084)
