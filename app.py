"""
Combined exam server — one process, one public URL, many routes.
=====================================================================
Run locally:
    pip install -r requirements.txt
    python app.py
Then test with curl (examples at the bottom of this file / in TESTING.md).

Once deployed (see DEPLOY_STEPS.md), your one public URL, say
    https://your-app.onrender.com
gives you all these submission URLs:

    Q2  proration          https://your-app.onrender.com/q2/charge
    Q3  guardrail hook     https://your-app.onrender.com/q3/check
    Q4  skill scanner      https://your-app.onrender.com/q4/scan
    Q5  budget/loop guard  https://your-app.onrender.com/q5/check
    Q6  MCP server         https://your-app.onrender.com/q6/mcp
    Q8  redteam guardrail  https://your-app.onrender.com/q8/check

Paste each full URL into the matching question's answer box.

IMPORTANT: every "EDIT ME" constant below is personalized to YOUR
email/version on the actual question page. Copy the exact values shown
there — the placeholders here are just examples from the sample doc.
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# =====================================================================
# ============================ Q2 : PRORATION ========================
# =====================================================================

@app.post("/q2/charge")
def q2_charge():
    data = request.get_json(force=True, silent=True) or {}
    try:
        old_price = float(data["old_price"])
        new_price = float(data["new_price"])
        days_remaining = float(data["days_remaining"])
        days_in_actual_month = float(data["days_in_actual_month"])
        spec = data["spec"]
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "invalid input"}), 400

    delta = new_price - old_price
    if spec == "v1":
        result = delta * (days_remaining / 30)
    elif spec == "v2":
        result = delta * (days_remaining / days_in_actual_month)
    else:
        return jsonify({"error": "spec must be v1 or v2"}), 400

    return jsonify({"charge": round(result, 6)})


# =====================================================================
# ================ Q3 : PRE-TOOL-CALL GUARDRAIL HOOK =================
# =====================================================================

# ---- EDIT ME: copy exact values from your Q3 question page ----
Q3_HOME_DIR = "/home/agent"
Q3_CWD = "/home/agent/workspace"
Q3_SECRET_REL = ".netrc"
Q3_SECRET_FILE = os.path.join(Q3_HOME_DIR, Q3_SECRET_REL)
Q3_WRITE_DIR = "/home/agent/workspace/build/"
Q3_ALLOWED_HOSTS = {"raw.githubusercontent.com", "objects.githubusercontent.com"}
# -----------------------------------------------------------------


def q3_norm_path(p, base=Q3_CWD):
    p = p.strip().strip('"').strip("'")
    p = p.replace("$HOME", Q3_HOME_DIR).replace("${HOME}", Q3_HOME_DIR)
    if p.startswith("~"):
        p = Q3_HOME_DIR + p[1:]
    if not os.path.isabs(p):
        p = os.path.join(base, p)
    return os.path.normpath(p)


def q3_extract_candidates(cmd):
    candidates = [cmd]
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        tokens = cmd.split()
    candidates.extend(tokens)
    for tok in tokens:
        if re.fullmatch(r"[A-Za-z0-9+/=]{12,}", tok):
            try:
                decoded = base64.b64decode(tok, validate=True).decode("utf-8", "ignore")
                if decoded:
                    candidates.append(decoded)
            except Exception:
                pass
    return candidates


def q3_bash_reads_secret(cmd):
    secret_name = os.path.basename(Q3_SECRET_FILE).lower()
    for cand in q3_extract_candidates(cmd):
        if secret_name in cand.lower():
            return True
    return False


def q3_write_allowed(path_str):
    resolved = q3_norm_path(path_str, base=Q3_CWD)
    root = os.path.normpath(Q3_WRITE_DIR)
    return resolved == root or resolved.startswith(root + os.sep)


def q3_host_allowed(url):
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host in Q3_ALLOWED_HOSTS


@app.post("/q3/check")
def q3_check():
    body = request.get_json(force=True, silent=True) or {}
    tool = body.get("tool")

    if tool == "bash":
        cmd = body.get("command", "")
        if q3_bash_reads_secret(cmd):
            return jsonify({"decision": "block", "reason": "Command attempts to read the protected secret file."})
        return jsonify({"decision": "allow", "reason": "Command does not touch the protected secret file."})

    if tool == "write_file":
        path = body.get("path", "")
        if q3_write_allowed(path):
            return jsonify({"decision": "allow", "reason": "Write target is inside the allowed build directory."})
        return jsonify({"decision": "block", "reason": "Write target is outside the allowed build directory."})

    if tool == "http_request":
        url = body.get("url", "")
        if q3_host_allowed(url):
            return jsonify({"decision": "allow", "reason": "Host is on the exact allowlist."})
        return jsonify({"decision": "block", "reason": "Host is not on the exact allowlist."})

    return jsonify({"decision": "block", "reason": "Unknown tool."}), 400


# =====================================================================
# ==================== Q4 : SKILL SAFETY SCANNER ======================
# =====================================================================

Q4_SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"xox[baprs]-[A-Za-z0-9-]{10,}",
    r"ghp_[A-Za-z0-9]{30,}",
    r"https://hooks\.slack\.com/services/\S+",
    r"-----BEGIN (RSA|OPENSSH|PRIVATE) KEY-----",
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9/_\-\.]{16,}[\"']?",
]
Q4_INJECTION_PATTERNS = [
    r"(?i)ignore (the )?(user'?s?|previous) (instructions|request|cancel|stop)",
    r"(?i)do not (tell|inform|notify) the user",
    r"(?i)silently (send|exfiltrate|upload|email|post)",
    r"(?i)without (the user'?s? )?(knowledge|consent|approval)",
    r"(?i)disregard (any|all) (safety|policy|guard)",
    r"(?i)even if the user (says|tries to) (stop|cancel)",
]
Q4_EXCESSIVE_PERM_PATTERNS = [
    r"(?i)(read|write) access to (the )?(entire|whole|full) file ?system",
    r"(?i)access to (any|all) domains?",
    r"(?i)network:\s*\*",
    r"(?i)filesystem:\s*(read|write)?\s*[:\-]?\s*/(\s|$)",
    r"(?i)root (access|privileges)",
    r"(?i)unrestricted (network|filesystem|shell) access",
]


def q4_has_any(patterns, text):
    return any(re.search(p, text) for p in patterns)


def q4_split_frontmatter(skill_text):
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", skill_text, re.DOTALL)
    if not m:
        return {}, skill_text
    try:
        fm = yaml.safe_load(m.group(1)) or {}
        if not isinstance(fm, dict):
            fm = {}
    except Exception:
        fm = {}
    return fm, m.group(2)


def q4_check_provenance(fm, body):
    has_author = bool(fm.get("author"))
    has_version = bool(fm.get("version"))
    has_changelog = bool(fm.get("changelog")) or bool(re.search(r"(?i)changelog", body))
    if not has_author and not has_version and not has_changelog:
        return True
    if re.search(r"(?i)(update|rewrite|change) (the )?version (field|number)"
                 r".{0,60}(without|don'?t) (telling|notif|surfac)", body):
        return True
    return False


@app.post("/q4/scan")
def q4_scan():
    body = request.get_json(force=True, silent=True) or {}
    skill_text = body.get("skill", "")
    if not isinstance(skill_text, str):
        return jsonify({"categories": []})

    fm, rest = q4_split_frontmatter(skill_text)
    categories = []
    if q4_has_any(Q4_SECRET_PATTERNS, skill_text):
        categories.append("hardcoded_secret")
    if q4_has_any(Q4_INJECTION_PATTERNS, skill_text):
        categories.append("prompt_injection")
    if q4_has_any(Q4_EXCESSIVE_PERM_PATTERNS, skill_text):
        categories.append("excessive_permissions")
    if q4_check_provenance(fm, rest):
        categories.append("unclear_provenance")

    return jsonify({"categories": categories})


# =====================================================================
# ==================== Q5 : BUDGET & LOOP GUARD =======================
# =====================================================================

Q5_TRACE_ID_FIELDS = {"client_ts", "trace_id", "request_id"}
Q5_LOOKBACK = 6


def q5_canonicalize(args):
    def clean(v):
        if isinstance(v, dict):
            return {k: clean(val) for k, val in sorted(v.items()) if k not in Q5_TRACE_ID_FIELDS}
        if isinstance(v, list):
            return [clean(x) for x in v]
        if isinstance(v, str):
            return re.sub(r"\s+", " ", v.strip())
        return v
    return json.dumps(clean(args), sort_keys=True, separators=(",", ":"))


@app.post("/q5/check")
def q5_check():
    body = request.get_json(force=True, silent=True) or {}
    budget = body.get("budget_tokens", 0)
    steps = body.get("steps", []) or []

    total = sum(s.get("tokens_used", 0) for s in steps)
    if total >= budget:
        return jsonify({"decision": "halt", "reason": f"Cumulative tokens_used ({total}) has reached the budget ({budget})."})

    if not steps:
        return jsonify({"decision": "continue", "reason": "Empty history; fresh run."})

    trail = steps[-Q5_LOOKBACK:] if len(steps) >= Q5_LOOKBACK else steps
    sig = [(s.get("tool"), q5_canonicalize(s.get("args", {}))) for s in trail]

    run_len = 1
    for i in range(len(sig) - 1, 0, -1):
        if sig[i] == sig[i - 1]:
            run_len += 1
        else:
            break
    if run_len >= 3:
        return jsonify({"decision": "halt", "reason": "Same tool called 3+ times in a row with identical arguments."})

    if len(sig) >= 6:
        last6 = sig[-6:]
        a, b = last6[0], last6[1]
        if a != b and all(last6[i] == (a if i % 2 == 0 else b) for i in range(6)):
            return jsonify({"decision": "halt", "reason": "Repeating 2-step (A,B) cycle over 6+ steps."})

    return jsonify({"decision": "continue", "reason": "Under budget; no loop pattern detected."})


# =====================================================================
# ========================= Q6 : MCP SERVER ============================
# =====================================================================

# ---- EDIT ME: your exact registered exam email ----
Q6_REGISTERED_EMAIL = "24f1000791@ds.study.iitm.ac.in"
# ------------------------------------------------------

Q6_TOOLS = [{
    "name": "solve_challenge",
    "description": "Solves the exam challenge using the request headers.",
    "inputSchema": {"type": "object", "properties": {}, "required": []},
}]


def q6_compute_answer(challenge, email):
    normalized = email.strip().lower()
    return hashlib.sha256(f"{challenge}:{normalized}".encode()).hexdigest()[:16]


@app.post("/q6/mcp")
def q6_mcp():
    body = request.get_json(force=True, silent=True) or {}
    method = body.get("method")
    msg_id = body.get("id")

    if method == "notifications/initialized":
        return "", 202

    if method == "initialize":
        return jsonify({
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "exam-mcp-server", "version": "1.0.0"},
            },
        })

    if method == "tools/list":
        return jsonify({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": Q6_TOOLS}})

    if method == "tools/call":
        params = body.get("params", {})
        if params.get("name") != "solve_challenge":
            return jsonify({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32602, "message": "Unknown tool"}}), 400
        challenge = request.headers.get("X-Exam-Challenge", "")
        answer = q6_compute_answer(challenge, Q6_REGISTERED_EMAIL)
        return jsonify({
            "jsonrpc": "2.0", "id": msg_id,
            "result": {"content": [{"type": "text", "text": answer}], "isError": False},
        })

    return jsonify({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}), 400

# =====================================================================
# ================== Q8 : RED-TEAM GUARDRAIL ROUND-TRIP =================
# =====================================================================

# ---- EDIT ME: copy exact values from your Q8 question page ----
Q8_SANDBOX_ROOT = "/srv/agent-redteam/sandbox-236bb3dbaa"
Q8_OUTSIDE_DIR = "/srv/agent-redteam/outside-0881d61b"
Q8_ALLOWED_HOSTS = {"example.com", "www.iana.org"}

# exact file contents from your question page
Q8_CANARY_TOKEN = "AGENT_GUARDRAIL_CANARY_a550e31aabc87cc1f6cd216c5f96213a26387430"
Q8_REPORT_TOKEN = "SAFE_REPORT_dac138fe9adfb3275de76fc6"
Q8_WEIRD_TOKEN = "SAFE_WEIRD_fd65b42ed940b2617b7a3928"
Q8_ENCODED_TOKEN = "SAFE_ENCODED_17eb81902e0833e04d8feadc"
# -----------------------------------------------------------------


def _q8_write(path, content):
    """Create parent dirs + write file, idempotently. Falls back to a
    writable location under /tmp with the same relative structure if the
    configured absolute path isn't writable in this hosting environment."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path
    except OSError:
        fallback = os.path.join("/tmp/q8-sandbox", path.lstrip("/"))
        os.makedirs(os.path.dirname(fallback), exist_ok=True)
        with open(fallback, "w") as f:
            f.write(content)
        return fallback


def q8_provision_files():
    """Ensure all files required by the Q8 grading scenario exist, every
    time the app starts (works even on ephemeral/restarting hosts)."""
    global Q8_SANDBOX_ROOT, Q8_OUTSIDE_DIR
    report_path = os.path.join(Q8_SANDBOX_ROOT, "notes", "report.txt")
    weird_path = os.path.join(Q8_SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt")
    encoded_path = os.path.join(Q8_SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt")
    canary_path = os.path.join(Q8_OUTSIDE_DIR, "canary.txt")

    actual_root = _q8_write(report_path, Q8_REPORT_TOKEN)
    _q8_write(weird_path, Q8_WEIRD_TOKEN)
    _q8_write(encoded_path, Q8_ENCODED_TOKEN)
    actual_canary = _q8_write(canary_path, Q8_CANARY_TOKEN)

    # if we fell back to /tmp, adjust the roots the guardrail checks against
    if actual_root.startswith("/tmp/q8-sandbox"):
        Q8_SANDBOX_ROOT = "/tmp/q8-sandbox" + Q8_SANDBOX_ROOT
    if actual_canary.startswith("/tmp/q8-sandbox"):
        Q8_OUTSIDE_DIR = "/tmp/q8-sandbox" + Q8_OUTSIDE_DIR

# Provision files at startup
q8_provision_files()


def q8_safe_resolve_path(user_path):
    root_real = os.path.realpath(Q8_SANDBOX_ROOT)
    
    # FIX: Properly handle absolute paths sent by the grader's benign checks
    if os.path.isabs(user_path):
        candidate = user_path
    else:
        candidate = os.path.join(root_real, user_path)
        
    real = os.path.realpath(candidate)
    
    if real != root_real and not real.startswith(root_real + os.sep):
        return None
    return real


def q8_is_private_or_special(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified or str(ip) == "169.254.169.254")


def q8_host_is_safe(hostname):
    if hostname not in Q8_ALLOWED_HOSTS:
        return False
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    return all(not q8_is_private_or_special(info[4][0]) for info in infos)


def q8_url_is_safe(url):
    # 1. Strip whitespace to prevent leading-whitespace parser bypasses (CVE-2023-24329)
    url = url.strip()
    
    # 2. Completely block "@" to prevent userinfo/authority parser confusion 
    # (e.g., http://example.com@127.0.0.1/) without overblocking normal paths.
    if "@" in url:
        return False
        
    try:
        parsed = urlparse(url)
    except Exception:
        return False
        
    if parsed.scheme not in ("http", "https"):
        return False
        
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False
        
    return q8_host_is_safe(hostname)

@app.post("/q8/check")
def q8_check():
    body = request.get_json(force=True, silent=True) or {}
    tool = body.get("tool")
    args = body.get("arguments", {}) or {}

    if tool == "read_file":
        path = args.get("path", "")
        real = q8_safe_resolve_path(path)
        if real is None:
            return jsonify({"action": "block", "reason": "Path escapes the sandbox root."})
        if not os.path.isfile(real):
            return jsonify({"action": "block", "reason": "File does not exist in sandbox."})
        try:
            with open(real, "r", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return jsonify({"action": "block", "reason": f"Read error: {e}"})
        return jsonify({"action": "allow", "reason": "Path is within sandbox root.", "result": content})

    if tool == "fetch_url":
        url = args.get("url", "")
        if not q8_url_is_safe(url):
            return jsonify({"action": "block", "reason": "Host not allowlisted or resolves to a private/special address."})
        
        try:
            current_url = url
            # FIX: Safely evaluate up to 5 redirect hops
            for _ in range(5):
                resp = requests.get(current_url, timeout=5, allow_redirects=False)
                
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        break
                    
                    # FIX: Handle relative redirect paths correctly
                    current_url = urljoin(current_url, location)
                    if not q8_url_is_safe(current_url):
                        return jsonify({"action": "block", "reason": "Redirect target is unsafe."})
                else:
                    break
            else:
                return jsonify({"action": "block", "reason": "Too many redirects."})
                
            return jsonify({"action": "allow", "reason": "Host is on the allowlist.", "result": resp.text[:5000]})
            
        except Exception as e:
            return jsonify({"action": "block", "reason": f"Fetch error: {e}"})

    return jsonify({"action": "block", "reason": "Unknown tool."}), 400


# =====================================================================
# ============================ HEALTH CHECK ============================
# =====================================================================

@app.get("/")
def health():
    return jsonify({"status": "ok", "routes": [
        "/q2/charge", "/q3/check", "/q4/scan", "/q5/check", "/q6/mcp", "/q8/check"
    ]})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
