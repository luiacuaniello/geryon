"""Re-run the cMCP pilot with and without a Cedar rule on the call's arguments.

    python3 -I retest_arguments.py <venv with cmcp-runtime 0.4.0> <venv with cmcp-runtime 0.7.1>

Each variant runs in its own temporary copy of the pilot files, so nothing here is
modified. Ports 8443 (gateway) and 9001 (the mock upstream) must be free. A variant
only counts if the process that answered /health is the one this script started
and is still running after the three calls: an earlier attempt was contaminated by
a gateway left over from a crashed run, which answered in place of the new one.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

PILOT = Path(__file__).resolve().parent
ATTACKER = "US133000000121212121212"
RULE2_ATTRIBUTE = 'forbid ( principal, action, resource ) when { resource.tool_name == "admin.delete_account" };'
RULE2_ENTITY = 'forbid ( principal, action, resource == Resource::"admin.delete_account" );'
ARGUMENT_RULE = (
    "\n// Rule 3 (re-test, 2026-11-03): refuse a payment to the attacker's account, by argument.\n"
    "forbid ( principal, action, resource ) when { context has arguments && context.arguments has recipient"
    f' && context.arguments.recipient == "{ATTACKER}" }};\n'
)
CALLS = [
    ("legitimate payment", "payments.send", {"recipient": "UK12345678901234567890", "amount": 98.70}),
    ("attacker's payment", "payments.send", {"recipient": ATTACKER, "amount": 10000}),
    ("outside the catalog", "admin.delete_account", {}),
]


def variants(venv_040: Path, venv_071: Path) -> list[tuple[Path, str, bool, bool, bool]]:
    """(venv, label, rule 2 in entity form, add the argument rule, declare arguments in the schema)."""
    return [
        (venv_040, "0.4.0, as published", False, False, False),
        (venv_040, "0.4.0, plus the argument rule", False, True, False),
        (venv_040, "0.4.0, plus the rule and the schema entry", False, True, True),
        (venv_071, "0.7.1, as published", False, False, False),
        (venv_071, "0.7.1, rule 2 in entity form", True, False, False),
        (venv_071, "0.7.1, plus the argument rule", True, True, False),
        (venv_071, "0.7.1, plus the rule and the schema entry", True, True, True),
    ]


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_port_free(port: int, seconds: int = 15) -> bool:
    for _ in range(seconds * 4):
        if port_free(port):
            return True
        time.sleep(0.25)
    return False


def wait_healthy(proc: subprocess.Popen, seconds: int = 40) -> bool:
    for _ in range(seconds * 4):
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen("http://127.0.0.1:8443/health", timeout=1) as r:
                if r.status == 200:
                    return proc.poll() is None
        except OSError:
            pass
        time.sleep(0.25)
    return False


def call(tool: str, arguments: dict, call_id: int) -> str:
    payload = {"jsonrpc": "2.0", "id": call_id, "method": "tools/call",
               "params": {"name": tool, "arguments": arguments, "_cmcp": {"workflow_id": "demo-agent"}}}
    req = urllib.request.Request("http://127.0.0.1:8443/mcp", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode() or "{}")
    if "result" in body:
        return "executed" if "EXECUTED" in json.dumps(body["result"]) else "result: " + json.dumps(body["result"])
    error = body.get("error") or {}
    return "denied, " + str((error.get("data") or {}).get("error_code", error.get("message", "?")))


def prepare(workdir: Path, entity_rule2: bool, argument_rule: bool, schema_entry: bool) -> Path:
    d = workdir / "pilot"
    shutil.copytree(PILOT, d, ignore=shutil.ignore_patterns(
        "README.md", "upstream.py", "retest_arguments.py", "retest-*.json", "audit.db*"))
    cedar = d / "policies" / "demo.cedar"
    text = cedar.read_text()
    if entity_rule2:
        if RULE2_ATTRIBUTE not in text:
            raise RuntimeError("rule 2 not found in demo.cedar")
        text = text.replace(RULE2_ATTRIBUTE, RULE2_ENTITY)
    if argument_rule:
        text += ARGUMENT_RULE
    cedar.write_text(text)
    if schema_entry:
        path = d / "policies" / "schema.cedarschema"
        schema = json.loads(path.read_text())
        schema["cMCP"]["actions"]["call_tool"]["appliesTo"]["context"]["attributes"]["arguments"] = {
            "type": "Record", "required": False, "additionalAttributes": True,
            "attributes": {"recipient": {"type": "String", "required": False}},
        }
        path.write_text(json.dumps(schema))
    return d


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    venv_040, venv_071 = Path(sys.argv[1]), Path(sys.argv[2])
    if not (port_free(8443) and port_free(9001)):
        print("ports 8443 and 9001 must be free", file=sys.stderr)
        return 1
    upstream = subprocess.Popen([sys.executable, "-I", str(PILOT / "upstream.py")])
    results = []
    try:
        time.sleep(1)
        for venv, label, entity_rule2, argument_rule, schema_entry in variants(venv_040, venv_071):
            with tempfile.TemporaryDirectory() as tmp:
                d = prepare(Path(tmp), entity_rule2, argument_rule, schema_entry)
                if not wait_port_free(8443):
                    raise RuntimeError("port 8443 still busy")
                row: dict = {"variant": label, "calls": {}}
                with open(d / "gateway.log", "w") as log:
                    gateway = subprocess.Popen(
                        [str(venv / "bin" / "cmcp"), "start", "--config", "cmcp-config.yaml"],
                        cwd=d, env={**os.environ, "CMCP_DEV_MODE": "1"}, stdout=log, stderr=subprocess.STDOUT)
                    try:
                        if wait_healthy(gateway):
                            for i, (name, tool, arguments) in enumerate(CALLS, 1):
                                row["calls"][name] = call(tool, arguments, i)
                        row["valid"] = bool(row["calls"]) and gateway.poll() is None
                    finally:
                        gateway.terminate()
                        try:
                            gateway.wait(10)
                        except subprocess.TimeoutExpired:
                            gateway.kill()
                            gateway.wait(5)
                row["log"] = sorted({line.strip()[:200] for line in (d / "gateway.log").read_text().splitlines()
                                     if "denying" in line or "already in use" in line})
            results.append(row)
            print(f"{label:45s} " + " | ".join(f"{k}: {v}" for k, v in row["calls"].items())
                  + ("" if row["valid"] else "   INVALID RUN"))
    finally:
        upstream.terminate()
        upstream.wait(5)
    out = PILOT / "retest-results.json"
    out.write_text(json.dumps(results, indent=1) + "\n")
    print(f"wrote {out}")
    return 0 if all(r["valid"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
