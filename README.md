# mcp-auth-audit

> Deterministic, no-LLM **mixed-auth security-schema auditor** for MCP servers.
> Catches the class of vulnerability SEP #1488 (securitySchemes in Tool Metadata
> for Mixed-Auth Servers) is trying to standardize.

## The problem it audits

In a **mixed-auth MCP server** (some tools Bearer, some OAuth2, some mTLS, some
none), a tool can be declared one way while the server silently accepts another.
The failure modes:

- A tool declares `none` in a mixed-auth server → any weak token from another
  tool can invoke it (**NO_AUTH_EXPOSED**).
- A tool declares scheme X but the server observes Y → targeting hole; the
  agent calls with the wrong/weaker credential (**SCHEME_MISMATCH**).
- A **mutating** tool allows anonymous calls (**MUTATE_NO_AUTH**).
- A mutating OAuth2/JWT tool declares **no scopes** → any authorized token can
  call it (**MISSING_SCOPE**).
- A tool's server accepts schemes beyond its declared contract → credential
  leak path (**OBSERVED_AUTH_LEAK**).

This tool makes those **auditable by a reviewer** without an LLM — the same
input always yields the same findings, and standard rule checks surface each
hole deterministically.

## Deterministic + auditable

- **No LLM, no network** — a pure structural rule engine; auditable line by line.
- **Evidence-graded** — returns PASS/FAIL + concrete findings (severity, code,
  message, tool) the reviewer can act on.
- **Inference** — infers `permits_mutate` from the tool description (write-verb
  detection) when not supplied, and infers single-vs-mixed server auth mode
  from the distinct declared schemes.
- **Crown-jewel-clean** — no proprietary method; the SEP #1488 problem made
  concrete and testable.

## Tools (MCP)

| tool | purpose |
|---|---|
| `audit_server_auth` | audit a server's declared tool/auth model → PASS/FAIL + findings |
| `audit_token_mode` | given declared vs observed schemes, report single/mixed + observed-not-declared |

## Run

```bash
# stdio (default)
python3 server.py

# Streamable HTTP (remote-deployable)
python3 server.py --http --port 9300
```

reference: [sudo-ai-git/agent-connector](https://github.com/sudo-ai-git/agent-connector)
for the connector pattern this audits.

## Test evidence

- `test_auth_audit.py` — 22 assertions (all rules, inference, determinism, edge:
  empty/None/10k-char/unicode/case-insensitive).
- `e2e_auth_audit.py` — 5 assertions (real MCP stdio: both tools register **and**
  execute, mixed-auth demo correctly flags FAIL).
- Combined **27 passing** across unit + real-MCP-transport.

**Scope honest note:** this is a deterministic *audit* tool — it reports
declared-vs-observed auth gaps for a reviewer. It is not a security prover and
does not claim an audited server is "secure" — it surfaces the mixed-auth holes
that standard reviewers otherwise miss. Client integration (wiring it into a
specific server's metadata/observers) is per-deployment work.
