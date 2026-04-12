"""
routers/soar_execute.py

POST /api/soar/execute    — SSH into configured target host and run a single command
GET  /api/soar/ssh-config — get current SSH config (admin only)
POST /api/soar/ssh-config — save SSH config (admin only)
POST /api/soar/ssh-test   — test SSH connection (admin only)
"""

import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from storage import get_ssh_config, save_ssh_config, add_audit_log
from auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/soar", tags=["soar-execute"])


def _run_ssh(cmd: str) -> dict:
    """SSH into the configured host and run cmd. Returns stdout, stderr, exit_code."""
    try:
        import paramiko
    except ImportError:
        raise HTTPException(status_code=500, detail="paramiko not installed — run: pip install paramiko")

    cfg = get_ssh_config()
    if not cfg.get("host"):
        raise HTTPException(status_code=400, detail="SSH not configured. Go to Settings → SSH Config.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": cfg["host"],
        "port":     int(cfg.get("port", 22)),
        "username": cfg["username"],
        "timeout":  15,
    }

    key_path = cfg.get("key_path", "").strip()
    if key_path:
        connect_kwargs["key_filename"]  = key_path
        connect_kwargs["look_for_keys"] = False
        connect_kwargs["allow_agent"]   = False
    else:
        connect_kwargs["look_for_keys"] = True
        connect_kwargs["allow_agent"]   = True

    try:
        client.connect(**connect_kwargs)
        _, stdout, stderr = client.exec_command(cmd, timeout=30)
        out  = stdout.read().decode("utf-8", errors="replace").strip()
        err  = stderr.read().decode("utf-8", errors="replace").strip()
        code = stdout.channel.recv_exit_status()
        client.close()
        return {"stdout": out, "stderr": err, "exit_code": code, "success": code == 0}
    except paramiko.AuthenticationException:
        raise HTTPException(status_code=401, detail="SSH authentication failed. Check key path or credentials.")
    except paramiko.SSHException as e:
        raise HTTPException(status_code=502, detail=f"SSH error: {e}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Connection failed: {e}")


class ExecuteRequest(BaseModel):
    command:     str
    incident_id: Optional[int] = None
    label:       Optional[str] = None


class SSHConfigRequest(BaseModel):
    host:     str
    port:     int = 22
    username: str
    key_path: str = ""


@router.get("/ssh-config")
def get_config(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    cfg = get_ssh_config()
    return {k: v for k, v in cfg.items() if k != "id"}


@router.post("/ssh-config")
def set_config(body: SSHConfigRequest, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    cfg = save_ssh_config(body.host, body.port, body.username, body.key_path)
    return {k: v for k, v in cfg.items() if k != "id"}


@router.post("/ssh-test")
def test_connection(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    result = _run_ssh("echo sentinel_ok && hostname && whoami")
    if result["success"]:
        return {"ok": True, "output": result["stdout"]}
    raise HTTPException(status_code=502, detail=result["stderr"] or "Connection test failed")


@router.post("/execute")
def execute_command(body: ExecuteRequest, current_user: dict = Depends(get_current_user)):
    if not body.command.strip():
        raise HTTPException(status_code=400, detail="Command cannot be empty")

    result = _run_ssh(body.command.strip())

    label  = body.label or body.command[:80]
    detail = f"SOAR auto-executed: {label} | exit={result['exit_code']}"
    if body.incident_id:
        add_audit_log(current_user["username"], "soar_executed", "incident", body.incident_id, detail)
    else:
        add_audit_log(current_user["username"], "soar_executed", "system", None, detail)

    return result
