"""Registry-specific models."""

from pydantic import BaseModel, Field

from packages.common.models import Component, LifecycleStatus


class ComponentCreate(BaseModel):
    """Request to register a new component."""

    id: str
    type: str
    owner: str
    purpose: str
    publisher: str
    version: str
    content_hash: str
    definition_hash: str
    signature_status: str = "unsigned"
    risk_tier: int = 2
    permissions: dict = Field(default_factory=dict)
    autonomy: dict = Field(default_factory=dict)


class ComponentUpdate(BaseModel):
    """Request to update a component."""

    lifecycle: LifecycleStatus | None = None
    approval_status: str | None = None
    permissions: dict | None = None
    autonomy: dict | None = None


class ComponentQuery(BaseModel):
    """Query parameters for component lookup."""

    id: str | None = None
    type: str | None = None
    owner: str | None = None
    lifecycle: LifecycleStatus | None = None


class RegistryResponse(BaseModel):
    """Standard registry response."""

    success: bool
    message: str
    component: Component | None = None
    components: list[Component] | None = None
