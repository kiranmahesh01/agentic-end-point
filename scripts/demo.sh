#!/bin/bash
# Agentic Endpoint Security - Demo Script
# 
# This script demonstrates five key scenarios:
# (a) Allowed read - reading from an approved path
# (b) Denied shell - attempting shell execution (always denied)
# (c) Denied path traversal write - attempting to write with ..
# (d) Untrusted input + write = approval required
# (e) Kill switch then subsequent action denied

set -e

DEMO_AGENT_URL="${DEMO_AGENT_URL:-http://localhost:8090}"
BROKER_URL="${BROKER_URL:-http://localhost:8080}"
KILLSWITCH_URL="${KILLSWITCH_URL:-http://localhost:8086}"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     AGENTIC ENDPOINT SECURITY - DEMONSTRATION SCENARIOS     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if services are running
check_service() {
    local url=$1
    local name=$2
    if curl -s "${url}/health" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} ${name} is running"
        return 0
    else
        echo -e "  ${RED}✗${NC} ${name} is not running at ${url}"
        return 1
    fi
}

echo -e "${BLUE}Checking services...${NC}"
SERVICES_OK=true
check_service "$BROKER_URL" "Broker" || SERVICES_OK=false
check_service "$DEMO_AGENT_URL" "Demo Agent" || SERVICES_OK=false
check_service "$KILLSWITCH_URL" "Kill Switch" || SERVICES_OK=false

if [ "$SERVICES_OK" = false ]; then
    echo ""
    echo -e "${RED}Some services are not running. Please start them with:${NC}"
    echo "  make up"
    echo ""
    echo "Or run services locally with:"
    echo "  uvicorn services.broker.app:app --port 8080 &"
    echo "  uvicorn services.demo_agent.app:app --port 8090 &"
    echo "  uvicorn services.killswitch.app:app --port 8086 &"
    echo ""
    exit 1
fi

echo ""
echo -e "${GREEN}All services are running!${NC}"
echo ""

run_scenario() {
    local name=$1
    local description=$2
    
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Scenario: ${BOLD}${description}${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    response=$(curl -s -X POST "${DEMO_AGENT_URL}/run/${name}")
    
    success=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
    decision=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('decision', 'ERROR'))" 2>/dev/null || echo "ERROR")
    message=$(echo "$response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('message', 'Unknown error'))" 2>/dev/null || echo "Unknown error")
    
    if [ "$success" = "True" ] || [ "$success" = "true" ]; then
        echo -e "  ${GREEN}${message}${NC}"
    else
        echo -e "  ${RED}${message}${NC}"
    fi
    
    echo ""
    echo -e "  ${YELLOW}Decision: ${decision}${NC}"
    echo ""
}

# Scenario A: Allowed Read
run_scenario "allowed_read" "Read from approved path should be ALLOWED"

# Scenario B: Denied Shell
run_scenario "denied_shell" "Shell execution should be DENIED (agent has shell=false)"

# Scenario C: Denied Path Traversal
run_scenario "denied_path_traversal" "Write with path traversal (..) should be DENIED"

# Scenario D: Untrusted Input + Write = Approval Required
run_scenario "untrusted_write_approval" "Untrusted input + write should REQUIRE_APPROVAL"

# Scenario E: Kill Switch
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}Scenario: ${BOLD}Kill switch then subsequent action DENIED${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo "  Step 1: Activating kill switch..."
TASK_ID="task-demo-$(date +%s)"
kill_response=$(curl -s -X POST "${KILLSWITCH_URL}/v1/kill" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"agent:demo-coder\", \"task_ids\": [\"${TASK_ID}\"], \"reason\": \"Demo kill switch test\", \"initiated_by\": \"demo-script\"}")

kill_status=$(echo "$kill_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('status', 'unknown'))" 2>/dev/null || echo "unknown")
echo -e "  ${YELLOW}Kill switch status: ${kill_status}${NC}"

echo ""
echo "  Step 2: Terminating task in broker..."
curl -s -X POST "${BROKER_URL}/v1/terminate-task?task_id=${TASK_ID}" > /dev/null

echo ""
echo "  Step 3: Attempting action after kill switch..."
read_response=$(curl -s -X POST "${BROKER_URL}/v1/read_file" \
    -H "Content-Type: application/json" \
    -d "{
        \"user\": \"demo-user\",
        \"agent_identity\": \"agent:demo-coder\",
        \"agent_instance\": \"instance-demo\",
        \"agent_version\": \"1.0.0\",
        \"endpoint_id\": \"endpoint-001\",
        \"task_id\": \"${TASK_ID}\",
        \"declared_goal\": \"Read after kill\",
        \"tool_id\": \"test-tool\",
        \"tool_version\": \"1.0.0\",
        \"tool_definition_hash\": \"sha256:demo-coder-definition-hash-def456\",
        \"path\": \"/approved/workspace/test.txt\",
        \"input_trust\": \"trusted\"
    }")

decision=$(echo "$read_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('decision', 'ERROR'))" 2>/dev/null || echo "ERROR")
reason=$(echo "$read_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('reason', 'Unknown'))" 2>/dev/null || echo "Unknown")

if [ "$decision" = "DENY" ]; then
    echo -e "  ${GREEN}✓ After kill switch, action was DENIED as expected${NC}"
else
    echo -e "  ${RED}✗ Expected DENY but got ${decision}${NC}"
fi

echo ""
echo -e "  ${YELLOW}Decision: ${decision}${NC}"
echo -e "  ${YELLOW}Reason: ${reason}${NC}"
echo ""

# Summary
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}                         SUMMARY                              ${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}(a) Allowed read${NC}              - Reads from approved paths succeed"
echo -e "  ${RED}(b) Denied shell${NC}              - Shell execution is blocked"
echo -e "  ${RED}(c) Denied path traversal${NC}     - Path traversal attempts fail"
echo -e "  ${YELLOW}(d) Approval required${NC}         - Untrusted input triggers approval"
echo -e "  ${RED}(e) Kill switch${NC}               - Terminated tasks stay denied"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Demo complete. See docs/ for more information."
echo ""
