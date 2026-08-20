"""
Registry Service - Component Inventory

Port: 8081

The registry maintains the inventory of all known components (agents, skills,
tools, MCP servers, extensions, model artifacts). Unknown components are denied
by the PDP.

Key principle: If it's not in the registry, it doesn't exist for policy purposes.
"""

import logging
from datetime import datetime, timedelta
from typing import Any

from fastapi import FastAPI, HTTPException, status

from packages.common.models import (
    Autonomy,
    Component,
    ComponentType,
    LifecycleStatus,
    ApprovalStatus,
    Permissions,
    RiskTier,
)
from services.registry.models import (
    ComponentCreate,
    ComponentUpdate,
    RegistryResponse,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Registry",
    description="Component inventory service. Unknown component = deny.",
    version="0.1.0",
)

_components: dict[str, Component] = {}


def _seed_demo_components() -> None:
    """Seed the registry with demo components for testing."""
    now = datetime.utcnow()

    demo_coder = Component(
        id="agent:demo-coder",
        type=ComponentType.AGENT,
        owner="demo-user",
        purpose="Demonstration coding agent for testing the security framework",
        publisher="agentic-endpoint-security",
        version="1.0.0",
        content_hash="sha256:demo-coder-content-hash-abc123",
        definition_hash="sha256:demo-coder-definition-hash-def456",
        signature_status="signed",
        risk_tier=RiskTier.TIER_1,
        approval_status=ApprovalStatus.APPROVED,
        approval_expiry=now + timedelta(days=30),
        permissions=Permissions(
            files_read=["/approved/workspace"],
            files_write=["/approved/output"],
            shell=False,
            network_allowlist=["reports.internal.example"],
            secrets=[],
        ),
        autonomy=Autonomy(
            can_execute_without_approval=False,
            can_access_network=True,
            can_modify_files=True,
            can_spawn_processes=False,
            can_access_secrets=False,
        ),
        lifecycle=LifecycleStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )

    finance_skill = Component(
        id="skill:finance-report:1.4.2",
        type=ComponentType.SKILL,
        owner="finance-team",
        purpose="Generate financial reports from approved data sources",
        publisher="internal-skills",
        version="1.4.2",
        content_hash="sha256:finance-skill-content-hash-789xyz",
        definition_hash="sha256:finance-skill-definition-hash-abc789",
        signature_status="signed",
        risk_tier=RiskTier.TIER_2,
        approval_status=ApprovalStatus.APPROVED,
        approval_expiry=now + timedelta(days=90),
        permissions=Permissions(
            files_read=["/approved/workspace", "/data/finance"],
            files_write=["/approved/output/reports"],
            shell=False,
            network_allowlist=["reports.internal.example", "finance.internal.example"],
            secrets=["FINANCE_API_KEY"],
        ),
        autonomy=Autonomy(
            can_execute_without_approval=False,
            can_access_network=True,
            can_modify_files=True,
            can_spawn_processes=False,
            can_access_secrets=True,
        ),
        lifecycle=LifecycleStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )

    demo_rpa = Component(
        id="agent:demo-rpa",
        type=ComponentType.AGENT,
        owner="demo-user",
        purpose="Demonstration RPA agent for isolated desktop automation",
        publisher="agentic-endpoint-security",
        version="1.0.0",
        content_hash="sha256:demo-rpa-content-hash-rpa123",
        definition_hash="sha256:demo-rpa-definition-hash-rpa456",
        signature_status="signed",
        risk_tier=RiskTier.TIER_2,
        approval_status=ApprovalStatus.APPROVED,
        approval_expiry=now + timedelta(days=30),
        permissions=Permissions(
            files_read=["/approved/workspace"],
            files_write=["/approved/output"],
            shell=False,
            network_allowlist=[],
            secrets=[],
            computer_use=True,
        ),
        autonomy=Autonomy(
            can_execute_without_approval=False,
            can_access_network=False,
            can_modify_files=True,
            can_spawn_processes=False,
            can_access_secrets=False,
        ),
        lifecycle=LifecycleStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )

    _components[demo_coder.id] = demo_coder
    _components[finance_skill.id] = finance_skill
    _components[demo_rpa.id] = demo_rpa
    logger.info(f"Seeded {len(_components)} demo components")


_seed_demo_components()


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "registry"}


@app.get("/v1/components", response_model=RegistryResponse)
async def list_components(
    type: str | None = None,
    lifecycle: str | None = None,
    owner: str | None = None,
) -> RegistryResponse:
    """List all registered components with optional filters."""
    components = list(_components.values())

    if type:
        components = [c for c in components if c.type.value == type]
    if lifecycle:
        components = [c for c in components if c.lifecycle.value == lifecycle]
    if owner:
        components = [c for c in components if c.owner == owner]

    return RegistryResponse(
        success=True,
        message=f"Found {len(components)} components",
        components=components,
    )


@app.get("/v1/components/{component_id}", response_model=RegistryResponse)
async def get_component(component_id: str) -> RegistryResponse:
    """
    Get a specific component by ID.

    This is the critical lookup for policy decisions.
    Unknown component = DENY at the PDP.
    """
    component = _components.get(component_id)
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component not found: {component_id}",
        )

    return RegistryResponse(
        success=True,
        message="Component found",
        component=component,
    )


@app.post("/v1/components", response_model=RegistryResponse, status_code=status.HTTP_201_CREATED)
async def register_component(request: ComponentCreate) -> RegistryResponse:
    """
    Register a new component.

    New components start in PROPOSED lifecycle and PENDING approval status.
    They cannot be used until approved.
    """
    if request.id in _components:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Component already exists: {request.id}",
        )

    now = datetime.utcnow()

    try:
        component_type = ComponentType(request.type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid component type: {request.type}",
        )

    try:
        risk_tier = RiskTier(request.risk_tier)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid risk tier: {request.risk_tier}",
        )

    component = Component(
        id=request.id,
        type=component_type,
        owner=request.owner,
        purpose=request.purpose,
        publisher=request.publisher,
        version=request.version,
        content_hash=request.content_hash,
        definition_hash=request.definition_hash,
        signature_status=request.signature_status,
        risk_tier=risk_tier,
        approval_status=ApprovalStatus.PENDING,
        permissions=Permissions(**request.permissions) if request.permissions else Permissions(),
        autonomy=Autonomy(**request.autonomy) if request.autonomy else Autonomy(),
        lifecycle=LifecycleStatus.PROPOSED,
        created_at=now,
        updated_at=now,
    )

    _components[component.id] = component
    logger.info(f"Registered new component: {component.id}")

    return RegistryResponse(
        success=True,
        message="Component registered (pending approval)",
        component=component,
    )


@app.patch("/v1/components/{component_id}", response_model=RegistryResponse)
async def update_component(component_id: str, request: ComponentUpdate) -> RegistryResponse:
    """Update a component's status or permissions."""
    component = _components.get(component_id)
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component not found: {component_id}",
        )

    if request.lifecycle:
        component.lifecycle = request.lifecycle

    if request.approval_status:
        try:
            component.approval_status = ApprovalStatus(request.approval_status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid approval status: {request.approval_status}",
            )

    if request.permissions:
        component.permissions = Permissions(**request.permissions)

    if request.autonomy:
        component.autonomy = Autonomy(**request.autonomy)

    component.updated_at = datetime.utcnow()
    _components[component_id] = component
    logger.info(f"Updated component: {component_id}")

    return RegistryResponse(
        success=True,
        message="Component updated",
        component=component,
    )


@app.post("/v1/components/{component_id}/suspend", response_model=RegistryResponse)
async def suspend_component(component_id: str, reason: str = "No reason provided") -> RegistryResponse:
    """
    Suspend a component immediately.

    This is called by the kill switch to prevent further use of a component.
    Suspended components are denied by the PDP.
    """
    component = _components.get(component_id)
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component not found: {component_id}",
        )

    component.lifecycle = LifecycleStatus.SUSPENDED
    component.updated_at = datetime.utcnow()
    _components[component_id] = component

    logger.warning(f"SUSPENDED component {component_id}: {reason}")

    return RegistryResponse(
        success=True,
        message=f"Component suspended: {reason}",
        component=component,
    )


@app.post("/v1/components/{component_id}/activate", response_model=RegistryResponse)
async def activate_component(component_id: str) -> RegistryResponse:
    """Activate a suspended or approved component."""
    component = _components.get(component_id)
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component not found: {component_id}",
        )

    if component.approval_status != ApprovalStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Component must be approved before activation",
        )

    component.lifecycle = LifecycleStatus.ACTIVE
    component.updated_at = datetime.utcnow()
    _components[component_id] = component

    logger.info(f"Activated component: {component_id}")

    return RegistryResponse(
        success=True,
        message="Component activated",
        component=component,
    )


@app.delete("/v1/components/{component_id}", response_model=RegistryResponse)
async def retire_component(component_id: str) -> RegistryResponse:
    """Mark a component as retired (soft delete)."""
    component = _components.get(component_id)
    if not component:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Component not found: {component_id}",
        )

    component.lifecycle = LifecycleStatus.RETIRED
    component.updated_at = datetime.utcnow()
    _components[component_id] = component

    logger.info(f"Retired component: {component_id}")

    return RegistryResponse(
        success=True,
        message="Component retired",
        component=component,
    )


@app.get("/v1/verify/{component_id}")
async def verify_component(component_id: str, definition_hash: str | None = None) -> dict[str, Any]:
    """
    Quick verification endpoint for PDP.

    Returns minimal data needed for policy decisions.
    """
    component = _components.get(component_id)

    if not component:
        return {
            "known": False,
            "active": False,
            "approved": False,
            "reason": "Component not found in registry",
        }

    is_active = component.lifecycle == LifecycleStatus.ACTIVE
    is_approved = component.approval_status == ApprovalStatus.APPROVED

    hash_match = True
    if definition_hash and component.definition_hash != definition_hash:
        hash_match = False

    return {
        "known": True,
        "active": is_active,
        "approved": is_approved,
        "hash_match": hash_match,
        "risk_tier": component.risk_tier.value,
        "permissions": component.permissions.model_dump(),
        "lifecycle": component.lifecycle.value,
        "reason": "OK" if (is_active and is_approved and hash_match) else "Component not usable",
    }


def get_component_sync(component_id: str) -> Component | None:
    """Synchronous helper for internal use."""
    return _components.get(component_id)


def get_components_store() -> dict[str, Component]:
    """Get the components store (for testing)."""
    return _components


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8081)
