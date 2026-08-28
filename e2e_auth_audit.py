#!/usr/bin/env python3
"""Real MCP stdio E2E for mcp-auth-audit — proves the tools register + execute
over the protocol, not just unit-level."""
import json, os, subprocess, sys
sys.path.insert(0, "/home/sudosudo/mcp-auth-audit")
S = os.path.join("/home/sudosudo/mcp-auth-audit", "server.py")

PASS=FAIL=0
def check(n,c,d=""):
    global PASS,FAIL
    if c: PASS+=1; print(f"  PASS: {n}")
    else: FAIL+=1; print(f"  FAIL: {n} {d}")

def call_tool(name, args):
    proc = subprocess.Popen([sys.executable, S], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    def send(o): proc.stdin.write(json.dumps(o)+"\n"); proc.stdin.flush()
    def recv():
        while True:
            line = proc.stdout.readline()
            if not line: return None
            try: return json.loads(line)
            except Exception: continue
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}})
    recv(); send({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
    send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    tl = recv()
    send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":args}})
    res = recv()
    proc.stdin.close()
    try: proc.wait(timeout=6)
    except Exception: proc.kill()
    return tl, res

print("=== tools/list ===")
tl,_ = call_tool("audit_server_auth", {})
names = [t.get("name") for t in tl["result"]["tools"]] if tl and "result" in tl else []
print("  tools:", names)
check("audit_server_auth registered", "audit_server_auth" in names)
check("audit_token_mode registered", "audit_token_mode" in names)

print("\n=== audit_server_auth call (mixed-auth demo!) ===")
_,res = call_tool("audit_server_auth", {"tools":[
    {"name":"read_file","description":"read a file","declared_scheme":"bearer"},
    {"name":"write_file","description":"write a file","declared_scheme":"bearer","permits_mutate":True},
    {"name":"reset_offsets","description":"reset the connector offsets","declared_scheme":"none","permits_mutate":True},
    {"name":"create_token","description":"issue a token","declared_scheme":"oauth2","declared_scopes":["admin"],"permits_mutate":True,"observed_schemes":["oauth2","bearer"]},
]})
txt = res["result"]["content"][0]["text"] if res and "result" in res else None
print("  result head:", (txt or "")[:110].replace("\n"," "))
check("audit_server_auth executes over MCP", txt is not None)
check("flags mixed-auth FAIL (no-auth reset)", txt and '"passed": false' in txt, (txt or "")[:150])

print("\n=== audit_token_mode call ===")
_,res = call_tool("audit_token_mode", {"declared_schemes":["bearer","oauth2"],"observed_schemes":["bearer","oauth2","jwt"]})
txt = res["result"]["content"][0]["text"] if res and "result" in res else None
check("audit_token_mode executes", txt and "multi" in txt)

print("\n--- E2E RESULT:", PASS, "passed,", FAIL, "failed ---")
sys.exit(1 if FAIL else 0)
