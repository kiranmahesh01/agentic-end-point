"""Demo agent models."""

from pydantic import BaseModel
from typing import Any


class DemoScenario(BaseModel):
    """A demo scenario to execute."""

    name: str
    description: str


class ScenarioResult(BaseModel):
    """Result of executing a demo scenario."""

    scenario: str
    success: bool
    decision: str
    message: str
    details: dict[str, Any] = {}
