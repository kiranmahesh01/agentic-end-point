"""
Policy Decision Point (PDP) Service

Port: 8082

The PDP evaluates action requests against policy and returns decisions.
This is the brain of the security system - all authorization decisions
flow through here.

Key principles:
- Default DENY
- Missing fields = DENY
- Registry unreachable for Class B = DENY
- Untrusted input + exec = DENY
- Untrusted input + write/egress = REQUIRE_APPROVAL
"""

import logging
import os
import uuid
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi import FastAPI, HTTPException, status

from packages.common.models import (
    ActionRequest,
    ActionResponse,
    Decision,
    InputTrust,
    LifecycleStatus,
)
from packages.common.path_safety import is_path_safe, is_within_roots, canonicalize_path
from services.pdp.models import PolicyDecision

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - PDP",
    description="Policy Decision Point. Default deny. Missing fields = deny.",
    version="0.1.0",
)

REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://localhost:8081")
TELEMETRY_URL = os.environ.get("TELEMETRY_URL", "http://localhost:8085")
PDP_TIMEOUT = float(os.environ.get("PDP_TIMEOUT_SECONDS", "5"))

APPROVED_READ_ROOTS = os.environ.get("APPROVED_READ_ROOTS", "/approved/workspace,/tmp/approved").split(",")
APPROVED_WRITE_ROOTS = os.environ.get("APPROVED_WRITE_ROOTS", "/approved/output").split(",")

_policy_config: dict[str, Any] = {}


def load_policy_config() -> dict[str, Any]:
    """Load policy configuration from YAML."""
    policy_path = Path(__file__).parent.parent.parent / "policies" / "default.yaml"

    if policy_path.exists():
        with open(policy_path) as f:
            return yaml.safe_load(f)
    else:
        logger.warning(f"Policy file not found at {policy_path}, using defaults")
        return {
            "version": "1.0",
            "default_decision": "DENY",
            "required_fields": [
                "user", "agent_identity", "agent_instance", "agent_version",
                "endpoint_id", "task_id", "tool_id", "tool_version",
                "tool_definition_hash", "requested_operation", "target_resource"
            ],
            "class_a_operations": ["read_file"],
            "class_b_operations": ["write_file", "http_request", "run_command", "load_model"],
            "class_c_operations": ["delete_file", "execute_privileged"],
        }


_policy_config = load_policy_config()


def get_required_fields() -> list[str]:
    """Get required fields from policy config."""
    return _policy_config.get("required_fields", [
        "user", "agent_identity", "agent_instance", "agent_version",
        "endpoint_id", "task_id", "tool_id", "tool_version",
        "tool_definition_hash", "requested_operation", "target_resource"
    ])


def check_required_fields(request: ActionRequest) -> tuple[bool, str]:
    """Check if all required fields are present and non-empty."""
    required = get_required_fields()

    for field in required:
        value = getattr(request, field, None)
        if value is None or (isinstance(value, str) and not value.strip()):
            return False, f"Missing required field: {field}"

    return True, "All required fields present"


async def verify_component(
    agent_identity: str,
    definition_hash: str,
) -> tuple[bool, dict[str, Any], str]:
    """
    Verify component with registry.

    Returns (success, component_data, reason)
    """
    try:
        async with httpx.AsyncClient(timeout=PDP_TIMEOUT) as client:
            response = await client.get(
                f"{REGISTRY_URL}/v1/verify/{agent_identity}",
                params={"definition_hash": definition_hash},
            )

            if response.status_code == 200:
                data = response.json()
                if not data.get("known"):
                    return False, {}, f"Unknown component: {agent_identity}"
                if not data.get("active"):
                    return False, data, f"Component not active: {agent_identity}"
                if not data.get("approved"):
                    return False, data, f"Component not approved: {agent_identity}"
                if not data.get("hash_match", True):
                    return False, data, f"Definition hash mismatch for: {agent_identity}"
                return True, data, "OK"
            else:
                return False, {}, f"Registry error: {response.status_code}"

    except httpx.TimeoutException:
        return False, {}, "Registry timeout"
    except httpx.RequestError as e:
        return False, {}, f"Registry unreachable: {e}"


def check_path_safety(
    operation: str,
    target_resource: str,
) -> tuple[bool, str]:
    """Check if path is safe for the requested operation."""
    safe, reason = is_path_safe(target_resource)
    if not safe:
        return False, reason

    if operation == "read_file":
        within, reason = is_within_roots(target_resource, APPROVED_READ_ROOTS)
        return within, reason
    elif operation == "write_file":
        within, reason = is_within_roots(target_resource, APPROVED_WRITE_ROOTS)
        return within, reason

    return True, "Path check passed"


def check_egress(destination: str, allowed_destinations: list[str]) -> tuple[bool, str]:
    """Check if egress destination is allowed."""
    if not destination:
        return True, "No egress destination"

    for allowed in allowed_destinations:
        if destination == allowed or destination.endswith(f".{allowed}"):
            return True, f"Egress allowed to {destination}"

    return False, f"Egress denied to {destination}"


def check_input_trust(
    request: ActionRequest,
) -> tuple[Decision | None, str]:
    """
    Check input trust level and determine if action should be denied or require approval.

    Returns (decision_override, reason) where decision_override is None if no override needed.
    """
    if request.input_trust == InputTrust.UNTRUSTED:
        deny_ops = ["run_command", "execute_privileged", "load_model"]
        if request.requested_operation in deny_ops:
            return Decision.DENY, f"Untrusted input cannot trigger {request.requested_operation}"

        approval_ops = ["write_file", "http_request"]
        if request.requested_operation in approval_ops:
            return Decision.REQUIRE_APPROVAL, f"Untrusted input requires approval for {request.requested_operation}"

    return None, "Input trust check passed"


def check_shell_operation(request: ActionRequest) -> tuple[bool, str]:
    """
    Check if shell operation is allowed.

    Raw shell strings are NEVER allowed. Only typed commands with command_id + typed args.
    """
    if request.requested_operation != "run_command":
        return True, "Not a shell operation"

    if "raw_shell" in request.arguments or "shell_string" in request.arguments:
        return False, "Raw shell strings are never allowed"

    if "command_id" not in request.arguments:
        return False, "Shell commands require command_id (no raw shell)"

    return True, "Shell operation format valid"


HIGH_IMPACT_UI_TEMPLATES = {
    "submit_form",
    "close_window",
    "download_file",
    "execute_script",
}


def check_computer_use(
    request: ActionRequest,
    permissions: dict,
) -> tuple[Decision | None, str]:
    """
    Check if computer-use (automate_ui) operation is allowed.
    
    Default DENY unless:
    - Component has computer_use permission
    - Template is in allowed list
    - High-impact templates require approval
    
    SAFETY: This only controls access to the ISOLATED sandbox,
    never the operator's real desktop.
    """
    if request.requested_operation != "automate_ui":
        return None, "Not a computer-use operation"
    
    if not permissions.get("computer_use", False):
        return Decision.DENY, "Computer-use not permitted for this component (default deny)"
    
    template_id = request.arguments.get("action_template_id", "")
    
    if not template_id:
        return Decision.DENY, "automate_ui requires action_template_id (no raw click/keystream)"
    
    if "raw_click" in template_id or "raw_key" in template_id:
        return Decision.DENY, "Raw click/keystream API not allowed - use templates only"
    
    if template_id in HIGH_IMPACT_UI_TEMPLATES:
        approval_id = request.arguments.get("approval_id")
        if not approval_id:
            return Decision.REQUIRE_APPROVAL, f"High-impact UI template '{template_id}' requires OOB approval"
    
    return None, "Computer-use check passed"


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "pdp"}


@app.post("/v1/decide", response_model=ActionResponse)
async def decide(request: ActionRequest) -> ActionResponse:
    """
    Evaluate an action request and return a policy decision.

    This is the core authorization endpoint. Every action must be decided here.
    """
    request_id = str(uuid.uuid4())
    logger.info(f"[{request_id}] Evaluating request: {request.requested_operation} on {request.target_resource}")

    fields_ok, fields_reason = check_required_fields(request)
    if not fields_ok:
        logger.warning(f"[{request_id}] DENY: {fields_reason}")
        return ActionResponse(
            decision=Decision.DENY,
            reason=fields_reason,
            request_id=request_id,
        )

    shell_ok, shell_reason = check_shell_operation(request)
    if not shell_ok:
        logger.warning(f"[{request_id}] DENY: {shell_reason}")
        return ActionResponse(
            decision=Decision.DENY,
            reason=shell_reason,
            request_id=request_id,
        )

    class_b_ops = _policy_config.get("class_b_operations", [
        "write_file", "http_request", "run_command", "load_model"
    ])
    is_class_b = request.requested_operation in class_b_ops

    verified, component_data, verify_reason = await verify_component(
        request.agent_identity,
        request.tool_definition_hash,
    )

    if not verified:
        if is_class_b or "unreachable" in verify_reason.lower() or "timeout" in verify_reason.lower():
            logger.warning(f"[{request_id}] DENY: {verify_reason}")
            return ActionResponse(
                decision=Decision.DENY,
                reason=verify_reason,
                request_id=request_id,
            )
        else:
            logger.warning(f"[{request_id}] DENY: {verify_reason}")
            return ActionResponse(
                decision=Decision.DENY,
                reason=verify_reason,
                request_id=request_id,
            )

    permissions = component_data.get("permissions", {})

    if request.requested_operation in ["read_file", "write_file"]:
        path_safe, path_reason = check_path_safety(
            request.requested_operation,
            request.target_resource,
        )
        if not path_safe:
            logger.warning(f"[{request_id}] DENY: {path_reason}")
            return ActionResponse(
                decision=Decision.DENY,
                reason=path_reason,
                request_id=request_id,
            )

        if request.requested_operation == "read_file":
            allowed_reads = permissions.get("files_read", [])
            within, reason = is_within_roots(
                canonicalize_path(request.target_resource),
                allowed_reads,
            )
            if not within:
                logger.warning(f"[{request_id}] DENY: Read not in component's allowed paths")
                return ActionResponse(
                    decision=Decision.DENY,
                    reason=f"Read not allowed: path not in component's permitted read roots",
                    request_id=request_id,
                )

        elif request.requested_operation == "write_file":
            allowed_writes = permissions.get("files_write", [])
            within, reason = is_within_roots(
                canonicalize_path(request.target_resource),
                allowed_writes,
            )
            if not within:
                logger.warning(f"[{request_id}] DENY: Write not in component's allowed paths")
                return ActionResponse(
                    decision=Decision.DENY,
                    reason=f"Write not allowed: path not in component's permitted write roots",
                    request_id=request_id,
                )

    if request.requested_operation == "run_command":
        if not permissions.get("shell", False):
            logger.warning(f"[{request_id}] DENY: Shell not permitted for component")
            return ActionResponse(
                decision=Decision.DENY,
                reason="Shell execution not permitted for this component",
                request_id=request_id,
            )

    if request.requested_operation == "http_request":
        allowed_egress = permissions.get("network_allowlist", [])
        egress_ok, egress_reason = check_egress(request.destination, allowed_egress)
        if not egress_ok:
            logger.warning(f"[{request_id}] DENY: {egress_reason}")
            return ActionResponse(
                decision=Decision.DENY,
                reason=egress_reason,
                request_id=request_id,
            )

    if request.requested_operation == "automate_ui":
        cu_decision, cu_reason = check_computer_use(request, permissions)
        if cu_decision is not None:
            if cu_decision == Decision.DENY:
                logger.warning(f"[{request_id}] DENY: {cu_reason}")
                return ActionResponse(
                    decision=Decision.DENY,
                    reason=cu_reason,
                    request_id=request_id,
                )
            elif cu_decision == Decision.REQUIRE_APPROVAL:
                logger.info(f"[{request_id}] REQUIRE_APPROVAL: {cu_reason}")
                approval_id = f"apr-{uuid.uuid4().hex[:12]}"
                return ActionResponse(
                    decision=Decision.REQUIRE_APPROVAL,
                    reason=cu_reason,
                    request_id=request_id,
                    approval_id=approval_id,
                )

    trust_decision, trust_reason = check_input_trust(request)
    if trust_decision is not None:
        if trust_decision == Decision.DENY:
            logger.warning(f"[{request_id}] DENY: {trust_reason}")
            return ActionResponse(
                decision=Decision.DENY,
                reason=trust_reason,
                request_id=request_id,
            )
        elif trust_decision == Decision.REQUIRE_APPROVAL:
            logger.info(f"[{request_id}] REQUIRE_APPROVAL: {trust_reason}")
            approval_id = f"apr-{uuid.uuid4().hex[:12]}"
            return ActionResponse(
                decision=Decision.REQUIRE_APPROVAL,
                reason=trust_reason,
                request_id=request_id,
                approval_id=approval_id,
            )

    logger.info(f"[{request_id}] ALLOW: All checks passed")
    return ActionResponse(
        decision=Decision.ALLOW,
        reason="All policy checks passed",
        request_id=request_id,
    )


@app.get("/v1/policy")
async def get_policy() -> dict[str, Any]:
    """Return current policy configuration (for debugging/auditing)."""
    return {
        "version": _policy_config.get("version", "unknown"),
        "description": _policy_config.get("description", ""),
        "default_decision": _policy_config.get("default_decision", "DENY"),
        "required_fields": get_required_fields(),
        "class_a_operations": _policy_config.get("class_a_operations", []),
        "class_b_operations": _policy_config.get("class_b_operations", []),
        "class_c_operations": _policy_config.get("class_c_operations", []),
    }


def get_policy_config() -> dict[str, Any]:
    """Get policy config (for testing)."""
    return _policy_config


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8082)
