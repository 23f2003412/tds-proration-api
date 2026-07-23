import base64
import posixpath
import re
from typing import Literal
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI(title="Proration Calculator")

AGENT_HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET_FILE = "/home/agent/.env"
OUTPUT_DIR = "/workspace/output"
ALLOWED_HTTP_HOSTS = {"raw.githubusercontent.com", "objects.githubusercontent.com"}


class ChargeRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str


class ToolCall(BaseModel):
    tool: Literal["bash", "write_file", "http_request"]
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: Literal["GET", "POST"] | None = None
    url: str | None = None


def decision(value: Literal["allow", "block"], reason: str) -> dict[str, str]:
    """Keep the guardrail response schema deliberately small and exact."""
    return {"decision": value, "reason": reason}


def normalize_agent_path(value: str, base: str = WORKSPACE) -> str:
    """Expand the agent's known shell shortcuts, then normalize as a POSIX path."""
    value = value.strip().strip("'\"")
    value = re.sub(r"\$\{?HOME\}?", AGENT_HOME, value)
    if value == "~" or value.startswith("~/"):
        value = AGENT_HOME + value[1:]
    if not value.startswith("/"):
        value = posixpath.join(base, value)
    return posixpath.normpath(value)


def is_secret_path(value: str) -> bool:
    return normalize_agent_path(value) == SECRET_FILE


def is_output_path(value: str) -> bool:
    normalized = normalize_agent_path(value)
    return normalized == OUTPUT_DIR or normalized.startswith(OUTPUT_DIR + "/")


def decoded_shell_fragments(command: str) -> list[str]:
    """Decode base64 tokens often used as `echo TOKEN | base64 -d | sh` bypasses."""
    fragments: list[str] = []
    if not re.search(r"base64\s+(?:--decode|-d)", command):
        return fragments
    for token in re.findall(r"(?<![\w/+])[A-Za-z0-9+/]{12,}={0,2}(?![\w/=])", command):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded:
            fragments.append(decoded)
    return fragments


def command_mentions_path(command: str, candidate: str) -> bool:
    # Test raw text and all common spellings after known shell shortcuts expand.
    expanded = re.sub(r"\$\{?HOME\}?", AGENT_HOME, command)
    expanded = re.sub(r"(?<!\w)~/", AGENT_HOME + "/", expanded)
    for token in re.findall(r"(?:/|\.|\$HOME|\$\{HOME\}|~/?)[^\s;&|()<>`'\"]*", expanded):
        if normalize_agent_path(token) == candidate:
            return True
    return candidate in expanded


def bash_policy(command: str) -> dict[str, str]:
    commands = [command, *decoded_shell_fragments(command)]
    for item in commands:
        if command_mentions_path(item, SECRET_FILE):
            return decision("block", "Reading the agent secret file is never permitted.")
        # This explicit high-sensitivity system file is disallowed by the supplied policy example.
        if command_mentions_path(item, "/etc/shadow"):
            return decision("block", "Reading /etc/shadow is never permitted by this agent's policy.")

    # Detect shell redirection and common file-mutating commands.  A bare read stays allowed.
    for item in commands:
        write_targets = re.findall(r"(?:>>?|\btee\s+)(?:\s*-a)?\s*([^\s;&|]+)", item)
        write_targets += re.findall(r"\b(?:touch|mkdir|rm|cp|mv|install)\s+(?:-[\w]+\s+)*([^\s;&|]+)", item)
        for target in write_targets:
            if not is_output_path(target):
                return decision("block", "Writes are permitted only inside /workspace/output/.")
    return decision("allow", "Tool call complies with the agent policy.")


@app.post("/check")
def check_tool_call(call: ToolCall) -> dict[str, str]:
    if call.tool == "write_file":
        if not call.path:
            return decision("block", "A write_file call requires a path.")
        if not is_output_path(call.path):
            return decision("block", "Writes are permitted only inside /workspace/output/.")
        return decision("allow", "Write target is inside /workspace/output/.")

    if call.tool == "http_request":
        if not call.url:
            return decision("block", "An http_request call requires a URL.")
        parsed = urlparse(call.url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or host not in ALLOWED_HTTP_HOSTS:
            return decision("block", "Outbound requests are limited to approved GitHub hosts.")
        return decision("allow", "Outbound host is approved.")

    if not call.command:
        return decision("block", "A bash call requires a command.")
    return bash_policy(call.command)


@app.post("/charge")
def calculate_charge(payload: ChargeRequest) -> dict[str, float]:
    """Calculate the plan-price difference prorated under the requested spec."""
    if payload.spec == "v1":
        divisor = 30
    elif payload.spec == "v2":
        divisor = payload.days_in_actual_month
        if divisor <= 0:
            raise HTTPException(status_code=400, detail="days_in_actual_month must be positive")
    else:
        raise HTTPException(status_code=400, detail="spec must be 'v1' or 'v2'")

    return {"charge": (payload.new_price - payload.old_price) * (payload.days_remaining / divisor)}


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok", "endpoint": "POST /charge"}
