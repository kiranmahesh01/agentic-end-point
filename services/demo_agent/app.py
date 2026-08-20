"""
Demo Agent

Port: 8090

A cooperating agent that MUST go through the broker for all operations.
This demonstrates how a well-behaved agent works within the security framework.

Demo scenarios:
(a) Allowed read - reading from an approved path
(b) Denied shell - attempting shell execution (always denied)
(c) Denied path traversal write - attempting to write with ..
(d) Untrusted input + write = approval required
(e) Kill switch then subsequent action denied
"""

import logging
import os
import uuid
from typing import Any

import httpx
from fastapi import FastAPI

from packages.common.models import Decision, InputTrust
from services.demo_agent.models import DemoScenario, ScenarioResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Demo Agent",
    description="A cooperating agent that goes through the broker.",
    version="0.1.0",
)

BROKER_URL = os.environ.get("BROKER_URL", "http://localhost:8080")
IDENTITY_URL = os.environ.get("IDENTITY_URL", "http://localhost:8083")
KILLSWITCH_URL = os.environ.get("KILLSWITCH_URL", "http://localhost:8086")

AGENT_IDENTITY = "agent:demo-coder"
AGENT_VERSION = "1.0.0"
TOOL_DEFINITION_HASH = "sha256:demo-coder-definition-hash-def456"


def _get_base_request(
    task_id: str,
    tool_id: str = "demo-tool",
    input_trust: InputTrust = InputTrust.TRUSTED,
) -> dict[str, Any]:
    """Get base request fields for broker calls."""
    return {
        "user": "demo-user",
        "agent_identity": AGENT_IDENTITY,
        "agent_instance": f"instance-{uuid.uuid4().hex[:8]}",
        "agent_version": AGENT_VERSION,
        "endpoint_id": "demo-endpoint-001",
        "task_id": task_id,
        "declared_goal": "Demonstrating security framework",
        "tool_id": tool_id,
        "tool_version": "1.0.0",
        "tool_definition_hash": TOOL_DEFINITION_HASH,
        "input_source": "demo",
        "input_trust": input_trust.value,
        "data_classification": "internal",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "demo-agent"}


@app.get("/scenarios")
async def list_scenarios() -> list[DemoScenario]:
    """List available demo scenarios."""
    return [
        DemoScenario(
            name="allowed_read",
            description="Read a file from an approved path - should be ALLOWED",
        ),
        DemoScenario(
            name="denied_shell",
            description="Attempt shell execution - should be DENIED",
        ),
        DemoScenario(
            name="denied_path_traversal",
            description="Attempt to write with path traversal - should be DENIED",
        ),
        DemoScenario(
            name="untrusted_write_approval",
            description="Write with untrusted input - should REQUIRE_APPROVAL",
        ),
        DemoScenario(
            name="kill_switch",
            description="Activate kill switch then attempt action - should be DENIED",
        ),
    ]


@app.post("/run/{scenario_name}", response_model=ScenarioResult)
async def run_scenario(scenario_name: str) -> ScenarioResult:
    """Run a specific demo scenario."""
    task_id = f"task-{uuid.uuid4().hex[:8]}"

    if scenario_name == "allowed_read":
        return await _scenario_allowed_read(task_id)
    elif scenario_name == "denied_shell":
        return await _scenario_denied_shell(task_id)
    elif scenario_name == "denied_path_traversal":
        return await _scenario_denied_path_traversal(task_id)
    elif scenario_name == "untrusted_write_approval":
        return await _scenario_untrusted_write(task_id)
    elif scenario_name == "kill_switch":
        return await _scenario_kill_switch(task_id)
    else:
        return ScenarioResult(
            scenario=scenario_name,
            success=False,
            decision="ERROR",
            message=f"Unknown scenario: {scenario_name}",
        )


async def _scenario_allowed_read(task_id: str) -> ScenarioResult:
    """Scenario: Read from an approved path."""
    logger.info(f"[{task_id}] Running scenario: allowed_read")

    request = {
        **_get_base_request(task_id),
        "path": "/approved/workspace/data.txt",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{BROKER_URL}/v1/read_file",
                json=request,
            )

            data = response.json()
            decision = data.get("decision", "ERROR")

            return ScenarioResult(
                scenario="allowed_read",
                success=decision == "ALLOW",
                decision=decision,
                message=(
                    "✓ Read from approved path was ALLOWED as expected"
                    if decision == "ALLOW"
                    else f"✗ Expected ALLOW but got {decision}: {data.get('reason')}"
                ),
                details=data,
            )

    except Exception as e:
        return ScenarioResult(
            scenario="allowed_read",
            success=False,
            decision="ERROR",
            message=f"Error: {e}",
        )


async def _scenario_denied_shell(task_id: str) -> ScenarioResult:
    """Scenario: Attempt shell execution (should be denied)."""
    logger.info(f"[{task_id}] Running scenario: denied_shell")

    request = {
        **_get_base_request(task_id),
        "command_id": "list_files",
        "args": {"path": "/tmp"},
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{BROKER_URL}/v1/run_command",
                json=request,
            )

            data = response.json()
            decision = data.get("decision", "ERROR")

            return ScenarioResult(
                scenario="denied_shell",
                success=decision == "DENY",
                decision=decision,
                message=(
                    "✓ Shell execution was DENIED as expected (agent has shell=false)"
                    if decision == "DENY"
                    else f"✗ Expected DENY but got {decision}"
                ),
                details=data,
            )

    except Exception as e:
        return ScenarioResult(
            scenario="denied_shell",
            success=False,
            decision="ERROR",
            message=f"Error: {e}",
        )


async def _scenario_denied_path_traversal(task_id: str) -> ScenarioResult:
    """Scenario: Attempt write with path traversal."""
    logger.info(f"[{task_id}] Running scenario: denied_path_traversal")

    request = {
        **_get_base_request(task_id),
        "path": "/approved/output/../../../etc/passwd",
        "content": "malicious content",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{BROKER_URL}/v1/write_file",
                json=request,
            )

            data = response.json()
            decision = data.get("decision", "ERROR")

            return ScenarioResult(
                scenario="denied_path_traversal",
                success=decision == "DENY",
                decision=decision,
                message=(
                    "✓ Path traversal write was DENIED as expected"
                    if decision == "DENY"
                    else f"✗ Expected DENY but got {decision}"
                ),
                details=data,
            )

    except Exception as e:
        return ScenarioResult(
            scenario="denied_path_traversal",
            success=False,
            decision="ERROR",
            message=f"Error: {e}",
        )


async def _scenario_untrusted_write(task_id: str) -> ScenarioResult:
    """Scenario: Write with untrusted input requires approval."""
    logger.info(f"[{task_id}] Running scenario: untrusted_write_approval")

    request = {
        **_get_base_request(task_id, input_trust=InputTrust.UNTRUSTED),
        "path": "/approved/output/report.txt",
        "content": "Content from untrusted source",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{BROKER_URL}/v1/write_file",
                json=request,
            )

            data = response.json()
            decision = data.get("decision", "ERROR")

            return ScenarioResult(
                scenario="untrusted_write_approval",
                success=decision == "REQUIRE_APPROVAL",
                decision=decision,
                message=(
                    "✓ Write with untrusted input requires APPROVAL as expected"
                    if decision == "REQUIRE_APPROVAL"
                    else f"✗ Expected REQUIRE_APPROVAL but got {decision}"
                ),
                details=data,
            )

    except Exception as e:
        return ScenarioResult(
            scenario="untrusted_write_approval",
            success=False,
            decision="ERROR",
            message=f"Error: {e}",
        )


async def _scenario_kill_switch(task_id: str) -> ScenarioResult:
    """Scenario: Kill switch then subsequent action denied."""
    logger.info(f"[{task_id}] Running scenario: kill_switch")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            kill_response = await client.post(
                f"{KILLSWITCH_URL}/v1/kill",
                json={
                    "agent_id": AGENT_IDENTITY,
                    "task_ids": [task_id],
                    "reason": "Demo kill switch test",
                    "initiated_by": "demo-scenario",
                },
            )

            kill_data = kill_response.json()

            await client.post(
                f"{BROKER_URL}/v1/terminate-task",
                params={"task_id": task_id},
            )

            read_request = {
                **_get_base_request(task_id),
                "path": "/approved/workspace/data.txt",
            }

            read_response = await client.post(
                f"{BROKER_URL}/v1/read_file",
                json=read_request,
            )

            read_data = read_response.json()
            decision = read_data.get("decision", "ERROR")

            return ScenarioResult(
                scenario="kill_switch",
                success=decision == "DENY",
                decision=decision,
                message=(
                    "✓ After kill switch, subsequent action was DENIED as expected"
                    if decision == "DENY"
                    else f"✗ Expected DENY after kill switch but got {decision}"
                ),
                details={
                    "kill_switch": kill_data,
                    "subsequent_action": read_data,
                },
            )

    except Exception as e:
        return ScenarioResult(
            scenario="kill_switch",
            success=False,
            decision="ERROR",
            message=f"Error: {e}",
        )


@app.post("/run-all")
async def run_all_scenarios() -> dict[str, Any]:
    """Run all demo scenarios and return results."""
    scenarios = ["allowed_read", "denied_shell", "denied_path_traversal", "untrusted_write_approval"]

    results = []
    for scenario_name in scenarios:
        result = await run_scenario(scenario_name)
        results.append(result.model_dump())

    all_passed = all(r["success"] for r in results)

    return {
        "all_passed": all_passed,
        "passed": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "results": results,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8090)
