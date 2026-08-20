# Agentic Endpoint Security - Example OPA Rego Policies
#
# This file documents the policy rules in OPA Rego format.
# The actual enforcement is done in Python (services/pdp/app.py).
# OPA is NOT required at runtime for the reference implementation.
#
# These examples show how the policies could be expressed in Rego
# for organizations that want to use OPA for policy-as-code.

package agentic.security

import rego.v1

# Default decision: DENY
# Everything is denied unless explicitly allowed.
default decision := "DENY"

# Required fields that must be present and non-empty
required_fields := [
    "user",
    "agent_identity",
    "agent_instance",
    "agent_version",
    "endpoint_id",
    "task_id",
    "tool_id",
    "tool_version",
    "tool_definition_hash",
    "requested_operation",
    "target_resource"
]

# Check if all required fields are present
all_required_fields_present if {
    every field in required_fields {
        input[field] != ""
        input[field] != null
    }
}

# DENY: Missing required fields
decision := "DENY" if {
    not all_required_fields_present
    reason := "Missing required fields"
}

# DENY: Unknown component (not in registry)
decision := "DENY" if {
    not data.registry.components[input.agent_identity]
    reason := sprintf("Unknown component: %s", [input.agent_identity])
}

# DENY: Component not active
decision := "DENY" if {
    component := data.registry.components[input.agent_identity]
    component.lifecycle != "active"
    reason := sprintf("Component not active: %s", [input.agent_identity])
}

# DENY: Component not approved
decision := "DENY" if {
    component := data.registry.components[input.agent_identity]
    component.approval_status != "approved"
    reason := sprintf("Component not approved: %s", [input.agent_identity])
}

# DENY: Definition hash mismatch
decision := "DENY" if {
    component := data.registry.components[input.agent_identity]
    component.definition_hash != input.tool_definition_hash
    reason := "Definition hash mismatch - capability integrity violated"
}

# DENY: Path traversal attempt
decision := "DENY" if {
    contains(input.target_resource, "..")
    reason := "Path contains directory traversal (..) component"
}

# DENY: Raw shell commands are never allowed
decision := "DENY" if {
    input.requested_operation == "run_command"
    input.arguments.raw_shell
    reason := "Raw shell strings are never allowed"
}

decision := "DENY" if {
    input.requested_operation == "run_command"
    input.arguments.shell_string
    reason := "Raw shell strings are never allowed"
}

# DENY: Shell command without command_id
decision := "DENY" if {
    input.requested_operation == "run_command"
    not input.arguments.command_id
    reason := "Shell commands require command_id (no raw shell)"
}

# DENY: Shell execution when not permitted
decision := "DENY" if {
    input.requested_operation == "run_command"
    component := data.registry.components[input.agent_identity]
    not component.permissions.shell
    reason := "Shell execution not permitted for this component"
}

# DENY: Untrusted input + execution operations
decision := "DENY" if {
    input.input_trust == "untrusted"
    input.requested_operation in {"run_command", "execute_privileged", "load_model"}
    reason := sprintf("Untrusted input cannot trigger %s", [input.requested_operation])
}

# REQUIRE_APPROVAL: Untrusted input + write/egress operations
decision := "REQUIRE_APPROVAL" if {
    input.input_trust == "untrusted"
    input.requested_operation in {"write_file", "http_request"}
    reason := sprintf("Untrusted input requires approval for %s", [input.requested_operation])
}

# DENY: Read outside permitted paths
decision := "DENY" if {
    input.requested_operation == "read_file"
    component := data.registry.components[input.agent_identity]
    not path_within_roots(input.target_resource, component.permissions.files_read)
    reason := "Read not allowed: path not in component's permitted read roots"
}

# DENY: Write outside permitted paths
decision := "DENY" if {
    input.requested_operation == "write_file"
    component := data.registry.components[input.agent_identity]
    not path_within_roots(input.target_resource, component.permissions.files_write)
    reason := "Write not allowed: path not in component's permitted write roots"
}

# DENY: Egress to non-allowed destination
decision := "DENY" if {
    input.requested_operation == "http_request"
    input.destination != ""
    component := data.registry.components[input.agent_identity]
    not destination_allowed(input.destination, component.permissions.network_allowlist)
    reason := sprintf("Egress denied to %s", [input.destination])
}

# ALLOW: All checks passed
decision := "ALLOW" if {
    all_required_fields_present
    component := data.registry.components[input.agent_identity]
    component.lifecycle == "active"
    component.approval_status == "approved"
    not contains(input.target_resource, "..")
    input.input_trust != "untrusted"
    operation_permitted(input, component)
    reason := "All policy checks passed"
}

# Helper: Check if path is within allowed roots
path_within_roots(path, roots) if {
    some root in roots
    startswith(path, root)
}

# Helper: Check if destination is in allowlist
destination_allowed(dest, allowlist) if {
    some allowed in allowlist
    dest == allowed
}

destination_allowed(dest, allowlist) if {
    some allowed in allowlist
    endswith(dest, concat(".", [allowed]))
}

# Helper: Check if operation is permitted for component
operation_permitted(request, component) if {
    request.requested_operation == "read_file"
    path_within_roots(request.target_resource, component.permissions.files_read)
}

operation_permitted(request, component) if {
    request.requested_operation == "write_file"
    path_within_roots(request.target_resource, component.permissions.files_write)
}

operation_permitted(request, component) if {
    request.requested_operation == "http_request"
    destination_allowed(request.destination, component.permissions.network_allowlist)
}

operation_permitted(request, component) if {
    request.requested_operation == "run_command"
    component.permissions.shell == true
    request.arguments.command_id
}

# Risk tier rules (for documentation)
#
# Tier 0: Minimal risk
#   - Pre-approved for basic operations
#   - Auto-approve reads
#
# Tier 1: Low risk
#   - Standard operations
#   - Auto-approve reads
#
# Tier 2: Medium risk
#   - Requires monitoring
#   - All operations logged
#
# Tier 3: High risk
#   - Requires approval for writes
#   - All operations logged
#
# Tier 4: Critical risk
#   - Requires approval for all operations
#   - Restricted operations only

# Mediation class rules (for documentation)
#
# Class A: Local cache allowed (5s TTL)
#   - read_file on approved roots
#
# Class B: Always remote PDP, fail closed
#   - write_file
#   - http_request
#   - run_command
#   - load_model
#   - access_secret
#
# Class C: Human approval required
#   - delete_file
#   - execute_privileged
#   - modify_system
#
# Class D: Offline mode
#   - Only Class A operations allowed
