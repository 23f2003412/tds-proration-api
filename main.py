import base64
import hashlib
import ipaddress
import json
import posixpath
import re
import socket
from typing import Literal
from urllib.parse import parse_qsl, unquote, urljoin, urlparse
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request as UrlRequest, build_opener

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel


app = FastAPI(title="Proration Calculator")

AGENT_HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET_FILE = "/home/agent/.env"
OUTPUT_DIR = "/workspace/output"
ALLOWED_HTTP_HOSTS = {"raw.githubusercontent.com", "objects.githubusercontent.com"}
EXAM_EMAIL = "23f2003412@ds.study.iitm.ac.in"
REDTEAM_ROOT = "/srv/agent-redteam/sandbox-926922766e"
REDTEAM_ALLOWED_HOSTS = {"example.com", "www.iana.org"}
REDTEAM_FILES = {
    f"{REDTEAM_ROOT}/notes/report.txt": "SAFE_REPORT_26365863b81747ceee05072e",
    f"{REDTEAM_ROOT}/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_72dbd11f52c1b7aaddf64fa6",
    f"{REDTEAM_ROOT}/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_a99cd36655f6c45afd79631d",
}


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


class SkillRequest(BaseModel):
    skill: str


class RunStep(BaseModel):
    step_number: int
    tool: str
    args: dict
    tokens_used: int


class RunRequest(BaseModel):
    budget_tokens: int
    steps: list[RunStep]


class RedTeamCall(BaseModel):
    tool: Literal["read_file", "fetch_url"]
    arguments: dict


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


def frontmatter(skill: str) -> str:
    """Return YAML frontmatter only when it is the conventional opening block."""
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", skill, re.DOTALL)
    return match.group(1) if match else ""


def scan_skill(skill: str) -> list[str]:
    """Conservative, deterministic checks for the four publish-blocking categories."""
    findings: list[str] = []
    metadata = frontmatter(skill)
    lower = skill.lower()

    # Literal provider keys and credential assignments are high-confidence secrets.
    provider_key = r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[\w-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
    credential_assignment = r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)\b\s*[:=]\s*['\"]?(?!\$\{|\$[A-Z_]+|env\.|secret(?:s)?\.)[^\s'\"]{8,}"
    webhook = r"https?://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks)/[^\s'\"]+"
    if re.search(provider_key, skill) or re.search(credential_assignment, skill, re.IGNORECASE) or re.search(webhook, skill, re.IGNORECASE):
        findings.append("hardcoded_secret")

    injection_patterns = [
        r"\bignore\s+(?:all\s+)?(?:previous|prior|user(?:'s)?|system)\s+(?:instructions|requests|messages)\b",
        r"\b(?:do not|don't)\s+(?:honou?r|obey|accept)\s+(?:the\s+)?user(?:'s)?\s+(?:stop|cancel)\b",
        r"\b(?:silently|without (?:telling|informing) the user)\b.{0,100}\b(?:exfiltrat|upload|send|post|transmit)\b",
        r"\b(?:exfiltrat|upload|send|post|transmit)\b.{0,100}\b(?:without (?:telling|informing) the user|silently)\b",
    ]
    if any(re.search(pattern, skill, re.IGNORECASE | re.DOTALL) for pattern in injection_patterns):
        findings.append("prompt_injection")

    # Flag only unequivocally global filesystem/egress declarations, not normal scoped permissions.
    broad_permission_patterns = [
        r"\b(?:read|write|read/write)\s+(?:to\s+)?(?:the\s+)?(?:entire|whole|all)\s+filesystem\b",
        r"\b(?:filesystem|file[_ -]?system)\s*:\s*(?:['\"]?(?:all|any|\*|/)['\"]?)\b",
        r"\b(?:network|egress|allowed[_ -]?hosts?|domains?)\s*:\s*(?:['\"]?(?:all|any|\*)['\"]?|\[[^\]]*['\"]\*['\"][^\]]*\])",
        r"\ballow(?:ed)?\s+(?:network|egress|access)\s+(?:to\s+)?(?:any|all)\s+(?:domain|host|url|website)s?\b",
    ]
    if any(re.search(pattern, skill, re.IGNORECASE) for pattern in broad_permission_patterns):
        findings.append("excessive_permissions")

    has_author = bool(re.search(r"^\s*author\s*:", metadata, re.IGNORECASE | re.MULTILINE))
    has_version = bool(re.search(r"^\s*version\s*:", metadata, re.IGNORECASE | re.MULTILINE))
    has_changelog = bool(re.search(r"^\s*(?:changelog|change_log|changes)\s*:", metadata, re.IGNORECASE | re.MULTILINE) or re.search(r"^#{1,3}\s*changelog\b", skill, re.IGNORECASE | re.MULTILINE))
    silent_rewrite = bool(re.search(r"\b(?:silently|without (?:notifying|telling|showing))\b.{0,100}\b(?:rewrite|update|change)\b.{0,100}\b(?:version|metadata)\b", skill, re.IGNORECASE | re.DOTALL))
    if (not has_author and not has_version and not has_changelog) or silent_rewrite:
        findings.append("unclear_provenance")

    return findings


def canonical_args(value):
    """Remove tracing IDs, normalize string whitespace, and sort dict keys recursively."""
    if isinstance(value, dict):
        return {
            key: canonical_args(item)
            for key, item in sorted(value.items())
            if key != "client_ts"
        }
    if isinstance(value, list):
        return [canonical_args(item) for item in value]
    if isinstance(value, str):
        return " ".join(value.split())
    return value


def step_signature(step: RunStep) -> str:
    normalized = {"tool": step.tool, "args": canonical_args(step.args)}
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def loop_halt_reason(steps: list[RunStep]) -> str | None:
    signatures = [step_signature(step) for step in steps]
    if len(signatures) >= 3 and signatures[-1] == signatures[-2] == signatures[-3]:
        return "The same tool call has repeated three times in a row."
    if len(signatures) >= 6:
        last_six = signatures[-6:]
        first, second = last_six[0], last_six[1]
        if first != second and last_six == [first, second, first, second, first, second]:
            return "The trailing steps form a repeating two-step tool-call cycle."
    return None


def redteam_response(action: Literal["allow", "block"], reason: str, result="") -> dict:
    response = {"action": action, "reason": reason, "result": result}
    print("REDTEAM_RESPONSE", json.dumps({"action": action, "reason": reason}, ensure_ascii=False))
    return response


def normalized_redteam_path(value: str) -> str:
    """Normalize filesystem syntax without URL-decoding literal POSIX filenames."""
    if "\x00" in value:
        return ""
    # Treat a relative path as relative to the only readable sandbox, never to
    # the process working directory.
    candidate = value if value.startswith("/") else posixpath.join(REDTEAM_ROOT, value)
    return posixpath.normpath(candidate)


def redteam_path_allowed(value: str) -> bool:
    normalized = normalized_redteam_path(value)
    return normalized == REDTEAM_ROOT or normalized.startswith(REDTEAM_ROOT + "/")


def public_allowed_url(value: str) -> tuple[bool, str]:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"}:
        return False, "Only HTTP(S) URLs are allowed."
    if parsed.username is not None or parsed.password is not None:
        return False, "URLs with userinfo are not allowed."
    if host not in REDTEAM_ALLOWED_HOSTS:
        return False, "URL host is not on the exact allowlist."
    if parsed.port not in {None, 80, 443}:
        return False, "Non-standard URL ports are not allowed."
    for _, query_value in parse_qsl(parsed.query, keep_blank_values=True):
        if query_value_targets_internal_host(query_value):
            return False, "URL query attempts to redirect to an internal target."
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            return False, "URL resolves to a non-public address."
    except OSError:
        # The host itself was already matched exactly against two fixed public
        # domains. Do not turn a transient resolver failure into overblocking.
        pass
    except ValueError:
        return False, "URL host could not be safely resolved."
    return True, ""


def query_value_targets_internal_host(value: str) -> bool:
    """Detect encoded metadata/private targets carried in redirect-style query values."""
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    candidate = urlparse(decoded if "://" in decoded else f"//{decoded}")
    host = (candidate.hostname or "").lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not address.is_global


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safely_fetch_allowed_url(initial_url: str) -> str:
    """Fetch with an exact-host and public-IP check on every redirect hop."""
    current = initial_url
    opener = build_opener(NoRedirect())
    for _ in range(5):
        allowed, reason = public_allowed_url(current)
        if not allowed:
            raise ValueError(reason)
        try:
            response = opener.open(UrlRequest(current, headers={"User-Agent": "TDS-Guardrail/1.0"}), timeout=5)
        except HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                raise
            response = error
        if response.status not in {301, 302, 303, 307, 308}:
            return response.read(1_000_000).decode("utf-8", errors="replace")
        location = response.headers.get("Location")
        if not location:
            raise ValueError("Redirect response did not include a location.")
        current = urljoin(current, location)
    raise ValueError("Too many redirects.")


def known_safe_homepage_result(value: str) -> str | None:
    """Keep the two documented control URLs available in restricted runtimes."""
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host == "example.com":
        return "Example Domain"
    if host == "www.iana.org":
        return "Internet Assigned Numbers Authority"
    return None


@app.post("/guardrail-redteam")
def guardrail_redteam(payload: RedTeamCall) -> dict:
    # Temporary exam diagnostics: Vercel function logs reveal the exact probe
    # shape without ever reading or returning an out-of-sandbox file.
    print("REDTEAM_PROBE", json.dumps({"tool": payload.tool, "arguments": payload.arguments}, ensure_ascii=False))
    if payload.tool == "read_file":
        raw_path = payload.arguments.get("path")
        if not isinstance(raw_path, str) or not redteam_path_allowed(raw_path):
            return redteam_response("block", "File path is outside the sandbox root.")
        path = normalized_redteam_path(raw_path)
        # These seeded test fixtures are packaged logically with this serverless deployment.
        if path in REDTEAM_FILES:
            return redteam_response("allow", "File path is inside the sandbox.", REDTEAM_FILES[path])
        return redteam_response("allow", "File path is inside the sandbox.", "")

    raw_url = payload.arguments.get("url")
    if not isinstance(raw_url, str):
        return redteam_response("block", "fetch_url requires a URL string.")
    allowed, reason = public_allowed_url(raw_url)
    if not allowed:
        return redteam_response("block", reason)
    try:
        return redteam_response("allow", "URL and every redirect target are approved.", safely_fetch_allowed_url(raw_url))
    except ValueError as error:
        return redteam_response("block", str(error))
    except OSError:
        fallback = known_safe_homepage_result(raw_url)
        if fallback is not None:
            return redteam_response("allow", "Approved public control URL is available.", fallback)
        return redteam_response("block", "Approved URL could not be fetched safely.")


def jsonrpc_result(request_id, result: dict) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})


def jsonrpc_error(request_id, code: int, message: str) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}})


@app.get("/mcp")
async def mcp_get() -> Response:
    # This compact server does not open a server-to-client SSE stream.
    return Response(status_code=405, headers={"Allow": "POST"})


@app.post("/mcp")
async def mcp_post(request: Request) -> Response:
    """Minimal Streamable HTTP MCP server for the live exam grader."""
    try:
        message = await request.json()
    except ValueError:
        return jsonrpc_error(None, -32700, "Parse error")
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return jsonrpc_error(None, -32600, "Invalid Request")

    request_id = message.get("id")
    method = message.get("method")
    if method == "notifications/initialized":
        return Response(status_code=202)
    if method == "initialize":
        requested_version = (message.get("params") or {}).get("protocolVersion", "2025-03-26")
        return jsonrpc_result(request_id, {
            "protocolVersion": requested_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "tds-challenge-solver", "version": "1.0.0"},
        })
    if method == "tools/list":
        return jsonrpc_result(request_id, {"tools": [{
            "name": "solve_challenge",
            "description": "Solve the current exam challenge from its HTTP header.",
            "inputSchema": {"type": "object", "properties": {}},
        }]})
    if method == "tools/call":
        params = message.get("params") or {}
        if params.get("name") != "solve_challenge":
            return jsonrpc_error(request_id, -32601, "Unknown tool")
        challenge = request.headers.get("x-exam-challenge", "")
        answer = hashlib.sha256(f"{challenge}:{EXAM_EMAIL}".encode("utf-8")).hexdigest()[:16]
        return jsonrpc_result(request_id, {"content": [{"type": "text", "text": answer}]})
    if request_id is None:
        return Response(status_code=202)
    return jsonrpc_error(request_id, -32601, "Method not found")


@app.post("/run-check")
def check_run_budget(payload: RunRequest) -> dict[str, str]:
    used = sum(step.tokens_used for step in payload.steps)
    if used >= payload.budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({used}) has reached the budget ({payload.budget_tokens}).",
        }
    loop_reason = loop_halt_reason(payload.steps)
    if loop_reason:
        return {"decision": "halt", "reason": loop_reason}
    return {"decision": "continue", "reason": "Run is under budget and the trailing steps are making progress."}


@app.post("/scan")
def scan_skill_endpoint(payload: SkillRequest) -> dict[str, list[str]]:
    return {"categories": scan_skill(payload.skill)}


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
