"""
Telemetry Service

Port: 8085

Collects and stores telemetry events for auditing and observability.

Key principles:
- Never store secrets
- Never store model chain-of-thought
- OpenTelemetry GenAI conventions are Development status (not stable)
- Events queryable by trace_id
"""

import logging
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException, status

from services.telemetry.models import EventCreate, EventResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Telemetry",
    description="Audit event collection. No secrets. No chain-of-thought.",
    version="0.1.0",
)

_events: list[dict[str, Any]] = []

REDACT_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "chain_of_thought",
    "reasoning",
    "thinking",
}


def _redact_sensitive(data: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive fields from metadata."""
    redacted = {}
    for key, value in data.items():
        lower_key = key.lower()
        if any(sensitive in lower_key for sensitive in REDACT_KEYS):
            redacted[key] = "[REDACTED]"
        elif isinstance(value, dict):
            redacted[key] = _redact_sensitive(value)
        else:
            redacted[key] = value
    return redacted


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "telemetry"}


@app.post("/v1/events", response_model=EventResponse, status_code=status.HTTP_201_CREATED)
async def create_event(request: EventCreate) -> EventResponse:
    """
    Record a telemetry event.

    Sensitive fields are automatically redacted.
    """
    timestamp = datetime.utcnow()

    redacted_metadata = _redact_sensitive(request.metadata)

    event = {
        "event_id": request.event_id,
        "trace_id": request.trace_id,
        "timestamp": timestamp,
        "event_type": request.event_type,
        "user": request.user,
        "agent_identity": request.agent_identity,
        "agent_instance": request.agent_instance,
        "endpoint_id": request.endpoint_id,
        "task_id": request.task_id,
        "operation": request.operation,
        "target": request.target,
        "decision": request.decision,
        "reason": request.reason,
        "metadata": redacted_metadata,
    }

    _events.append(event)

    logger.info(
        f"Event {request.event_id}: {request.event_type} "
        f"({request.operation} -> {request.decision})"
    )

    return EventResponse(**event)


@app.get("/v1/events/{event_id}", response_model=EventResponse)
async def get_event(event_id: str) -> EventResponse:
    """Get a specific event by ID."""
    for event in _events:
        if event["event_id"] == event_id:
            return EventResponse(**event)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Event not found",
    )


@app.get("/v1/events")
async def list_events(
    trace_id: str | None = None,
    event_type: str | None = None,
    agent_identity: str | None = None,
    task_id: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """
    List events with optional filters.

    Primary use case: query by trace_id to see full request flow.
    """
    events = _events.copy()

    if trace_id:
        events = [e for e in events if e["trace_id"] == trace_id]

    if event_type:
        events = [e for e in events if e["event_type"] == event_type]

    if agent_identity:
        events = [e for e in events if e["agent_identity"] == agent_identity]

    if task_id:
        events = [e for e in events if e["task_id"] == task_id]

    events = events[-limit:]

    return {
        "count": len(events),
        "events": [EventResponse(**e).model_dump() for e in events],
    }


@app.get("/v1/trace/{trace_id}")
async def get_trace(trace_id: str) -> dict[str, Any]:
    """
    Get all events for a specific trace.

    This is the primary query pattern for understanding
    what happened during an action request.
    """
    trace_events = [e for e in _events if e["trace_id"] == trace_id]

    if not trace_events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trace not found",
        )

    trace_events.sort(key=lambda e: e["timestamp"])

    return {
        "trace_id": trace_id,
        "event_count": len(trace_events),
        "events": [EventResponse(**e).model_dump() for e in trace_events],
    }


@app.delete("/v1/events")
async def clear_events() -> dict[str, str]:
    """Clear all events (for testing only)."""
    _events.clear()
    return {"message": "All events cleared"}


def get_events_store() -> list[dict[str, Any]]:
    """Get events store (for testing)."""
    return _events


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8085)
