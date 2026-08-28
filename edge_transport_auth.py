#!/usr/bin/env python3
"""Adversarial transport edge cases for mcp-auth-audit — server must survive
malformed input over real MCP stdio."""
import json, os, subprocess, sys
S = os.path.join("/home/sudosudo/mcp-auth-audit", "server.py")
PASS=FAIL=0
def check(n,c,d=""):
    global PASS,FAIL
    if c: PASS+=1; print(f"  PASS: {n}")
    else: FAIL+=1; print(f"  FAIL: {n} {d}")

def raw_call(tool, args):
    proc = subprocess.Popen([sys.executable, S], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    def send(o): proc.stdin.write(json.dumps(o)+"\n"); proc.stdin.flush()
    def recv():
        while True:
            line = proc.stdout.readline()
            if not line: return None
            try: return json.loads(line)
            except Exception: continue
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"adv","version":"1"}}})
    recv(); send({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
    send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":args}})
    res = recv()
    # survival check: next valid call must work
    send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"audit_token_mode","arguments":{"declared_schemes":["bearer"],"observed_schemes":["bearer"]}}})
    alive = recv()
    proc.stdin.close()
    try: proc.wait(timeout=6)
    except Exception: proc.kill()
    return res, alive is not None

print("=== adversarial transport (server must survive each) ===")
for tool, args in [
    ("audit_server_auth", {"tools": "not-a-list"}),
    ("audit_server_auth", {}),
    ("audit_token_mode", {"declared_schemes": 123, "observed_schemes": None}),
    ("audit_token_mode", {}),
    ("nonexistent_tool", {}),
]:
    res, alive = raw_call(tool, args)
    check(f"{tool} bad/missing args -> server survives", alive)

# edge: tool arg entry with all-None description
res, alive = raw_call("audit_server_auth", {"tools":[{"name":"x"}]})
check("tool with only name -> server survives", alive)

print(f"\nauth-audit adversarial: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
