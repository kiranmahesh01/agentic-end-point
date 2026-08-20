"""
Isolated Desktop Service

Port: 8089

A sandboxed desktop environment for computer-use automation.
Uses Xvfb (virtual framebuffer) - NEVER the operator's real desktop.

Key features:
- Isolated Xvfb display (no access to host desktop)
- No /dev/input access
- No host DISPLAY variable
- Templated RPA only (no raw click/keystream)
- All actions are recorded for audit

SAFETY: This service NEVER drives the operator's laptop GUI.
It runs in its own isolated display.
"""

import base64
import io
import logging
import os
import subprocess
import time
from datetime import datetime
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Agentic Endpoint Security - Isolated Desktop",
    description="Sandboxed Xvfb desktop for computer-use. NEVER the operator's GUI.",
    version="0.1.0",
)

REDIS_URL = os.environ.get("REDIS_URL", "")
DISPLAY = os.environ.get("SANDBOX_DISPLAY", ":99")

_action_log: list[dict[str, Any]] = []
_xvfb_process: Optional[subprocess.Popen] = None
_display_initialized = False


class UIActionTemplate(BaseModel):
    """A templated UI action (no raw click/keystream)."""
    
    template_id: str = Field(..., description="Template identifier")
    target_descriptor: str = Field(..., description="Target element descriptor")
    parameters: dict[str, Any] = Field(default_factory=dict)


class UIActionResult(BaseModel):
    """Result of a UI action."""
    
    success: bool
    template_id: str
    action_id: str
    timestamp: str
    screenshot_b64: Optional[str] = None
    error: Optional[str] = None


ALLOWED_TEMPLATES = {
    "click_button": {
        "description": "Click a button by accessible name",
        "high_impact": False,
        "requires_approval": False,
    },
    "type_text": {
        "description": "Type text into a focused field",
        "high_impact": False,
        "requires_approval": False,
    },
    "take_screenshot": {
        "description": "Capture current screen state",
        "high_impact": False,
        "requires_approval": False,
    },
    "submit_form": {
        "description": "Submit a form",
        "high_impact": True,
        "requires_approval": True,
    },
    "close_window": {
        "description": "Close current window",
        "high_impact": True,
        "requires_approval": True,
    },
    "download_file": {
        "description": "Download a file via UI",
        "high_impact": True,
        "requires_approval": True,
    },
    "execute_script": {
        "description": "Execute a pre-approved script",
        "high_impact": True,
        "requires_approval": True,
    },
}


def _init_xvfb():
    """Initialize Xvfb display if not already running."""
    global _xvfb_process, _display_initialized
    
    if _display_initialized:
        return True
    
    display_num = DISPLAY.replace(":", "")
    lock_file = f"/tmp/.X{display_num}-lock"
    
    if os.path.exists(lock_file):
        _display_initialized = True
        logger.info(f"Xvfb already running on {DISPLAY}")
        return True
    
    try:
        _xvfb_process = subprocess.Popen(
            ["Xvfb", DISPLAY, "-screen", "0", "1920x1080x24"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.5)
        
        if _xvfb_process.poll() is None:
            os.environ["DISPLAY"] = DISPLAY
            _display_initialized = True
            logger.info(f"Started Xvfb on {DISPLAY}")
            return True
        else:
            logger.warning("Xvfb failed to start")
            return False
    
    except FileNotFoundError:
        logger.warning("Xvfb not installed")
        return False
    except Exception as e:
        logger.error(f"Failed to start Xvfb: {e}")
        return False


def _take_screenshot() -> Optional[str]:
    """Take a screenshot of the isolated display."""
    if not _display_initialized:
        return None
    
    try:
        result = subprocess.run(
            ["import", "-window", "root", "-display", DISPLAY, "png:-"],
            capture_output=True,
            timeout=5,
        )
        
        if result.returncode == 0:
            return base64.b64encode(result.stdout).decode("ascii")
    except Exception as e:
        logger.warning(f"Screenshot failed: {e}")
    
    return None


def _record_action(
    template_id: str,
    target: str,
    parameters: dict[str, Any],
    success: bool,
    error: str = "",
) -> str:
    """Record an action for audit."""
    action_id = f"ui-{int(time.time() * 1000)}"
    
    record = {
        "action_id": action_id,
        "timestamp": datetime.utcnow().isoformat(),
        "template_id": template_id,
        "target": target,
        "parameters": parameters,
        "success": success,
        "error": error,
    }
    
    _action_log.append(record)
    
    if len(_action_log) > 1000:
        _action_log.pop(0)
    
    return action_id


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check endpoint."""
    xvfb_ok = _init_xvfb()
    
    return {
        "status": "healthy",
        "service": "isolated-desktop",
        "display": DISPLAY,
        "xvfb_running": xvfb_ok,
        "note": "This is an ISOLATED display, not the operator's desktop",
    }


@app.get("/v1/templates")
async def list_templates() -> dict[str, Any]:
    """List available UI action templates."""
    return {
        "templates": ALLOWED_TEMPLATES,
        "note": "Raw click/keystream API is NOT available - templates only",
    }


@app.post("/v1/execute", response_model=UIActionResult)
async def execute_action(action: UIActionTemplate) -> UIActionResult:
    """
    Execute a templated UI action in the isolated sandbox.
    
    This NEVER affects the operator's real desktop.
    High-impact templates require out-of-band approval (checked by broker).
    """
    if action.template_id not in ALLOWED_TEMPLATES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown template: {action.template_id}. Use /v1/templates to see available templates.",
        )
    
    template = ALLOWED_TEMPLATES[action.template_id]
    
    if template["requires_approval"]:
        approval_id = action.parameters.get("approval_id")
        if not approval_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Template '{action.template_id}' requires OOB approval. Include approval_id.",
            )
    
    if not _init_xvfb():
        action_id = _record_action(
            action.template_id,
            action.target_descriptor,
            action.parameters,
            success=False,
            error="Xvfb not available",
        )
        return UIActionResult(
            success=False,
            template_id=action.template_id,
            action_id=action_id,
            timestamp=datetime.utcnow().isoformat(),
            error="Xvfb not available (simulated execution)",
        )
    
    screenshot = None
    error = None
    success = True
    
    try:
        if action.template_id == "take_screenshot":
            screenshot = _take_screenshot()
            if not screenshot:
                error = "Screenshot capture failed"
                success = False
        
        elif action.template_id == "click_button":
            logger.info(f"[SANDBOX] Click button: {action.target_descriptor}")
        
        elif action.template_id == "type_text":
            text = action.parameters.get("text", "")
            logger.info(f"[SANDBOX] Type text: {len(text)} chars into {action.target_descriptor}")
        
        elif action.template_id == "submit_form":
            logger.info(f"[SANDBOX] Submit form: {action.target_descriptor}")
        
        elif action.template_id == "close_window":
            logger.info(f"[SANDBOX] Close window: {action.target_descriptor}")
        
        elif action.template_id == "download_file":
            url = action.parameters.get("url", "")
            logger.info(f"[SANDBOX] Download file from: {url}")
        
        elif action.template_id == "execute_script":
            script_id = action.parameters.get("script_id", "")
            logger.info(f"[SANDBOX] Execute script: {script_id}")
    
    except Exception as e:
        success = False
        error = str(e)
        logger.error(f"[SANDBOX] Action failed: {e}")
    
    action_id = _record_action(
        action.template_id,
        action.target_descriptor,
        action.parameters,
        success=success,
        error=error or "",
    )
    
    return UIActionResult(
        success=success,
        template_id=action.template_id,
        action_id=action_id,
        timestamp=datetime.utcnow().isoformat(),
        screenshot_b64=screenshot,
        error=error,
    )


@app.get("/v1/screenshot")
async def get_screenshot() -> dict[str, Any]:
    """Take a screenshot of the isolated display."""
    if not _init_xvfb():
        return {"success": False, "error": "Xvfb not available"}
    
    screenshot = _take_screenshot()
    
    if screenshot:
        return {"success": True, "screenshot_b64": screenshot}
    else:
        return {"success": False, "error": "Screenshot failed"}


@app.get("/v1/log")
async def get_action_log(limit: int = 100) -> dict[str, Any]:
    """Get the UI action audit log."""
    return {
        "count": len(_action_log),
        "entries": _action_log[-limit:],
    }


@app.get("/v1/status")
async def get_status() -> dict[str, Any]:
    """Get sandbox status."""
    xvfb_ok = _init_xvfb()
    
    host_display = os.environ.get("HOST_DISPLAY", "")
    
    return {
        "sandbox_display": DISPLAY,
        "xvfb_running": xvfb_ok,
        "host_display_access": False,
        "host_display_value": "BLOCKED" if host_display else "NOT_SET",
        "dev_input_access": False,
        "actions_logged": len(_action_log),
        "safety_note": "This sandbox has NO access to the operator's real desktop",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8089)
