#!/usr/bin/env python3
"""
mcp-auth-audit — deterministic mixed-auth security-schema auditor.

Audits an MCP server's declared auth/security model for mixed-auth
vulnerabilities — the class of problem SEP #1488 (securitySchemes in Tool
Metadata for Mixed-Auth Servers) is trying to standardize. This tool makes that
problem *auditable*: given a server's tool list + its declared auth model, it
deterministically detects targeting holes and leaks WITHOUT an LLM.

Why it matters: in a mixed-auth server, one tool may be declared Bearer-only
while the server silently also accepts an OAuth token (or a tool with no auth
exposes an operation that needs it). The agent then calls with the wrong
credential and either fails or — worse — succeeds with a weaker-privilege token
inherited from another tool. That is the silent killer the securitySchemes SEP
targets. This tool makes a reviewer able to see it.

Deterministic: same input -> same findings. No network, no LLM, auditable
line by line. Crown-jewel-clean (no proprietary method).
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Valid MCP / OpenAPI-ish security scheme kinds.
KNOWN_SCHEMES = {"bearer", "oauth2", "mtls", "apikey", "basic", "none", "jwt", "anonymous"}


@dataclass
class ToolAuth:
    """A tool's declared auth + the auth kinds actually accepted (if observed)."""
    name: str
    declared_scheme: str          # e.g. 'bearer', 'oauth2', 'mtls', 'none'
    declared_scopes: List[str] = field(default_factory=list)
    observed_schemes: List[str] = field(default_factory=list)  # what the server actually accepts
    permits_mutate: bool = False   # does this tool write/act (vs read-only)?
    notes: str = ""


@dataclass
class AuditFinding:
    severity: str          # HIGH / MEDIUM / LOW / INFO
    code: str
    message: str
    tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MixedAuthAuditor:
    """Deterministic rules engine for mixed-auth targeting holes."""

    def __init__(self) -> None:
        self._findings: List[AuditFinding] = []

    # ------------------------------------------------------------------ core
    def audit(self, tools: List[ToolAuth], server_token_mode: str = "auto"
              ) -> Dict[str, Any]:
        """Audit a set of tools' auth declarations. Returns PASS/FAIL + findings.
        server_token_mode: 'single' (one auth mode server-wide) or 'multi'
        (mixed-auth, SEP #1488 case). 'auto' infers from the distinct schemes."""
        self._findings = []
        distinct = {t.declared_scheme.lower() for t in tools}
        if server_token_mode == "auto":
            server_token_mode = "multi" if len(distinct) > 1 else "single"

        for t in tools:
            self._check_scheme_validity(t)
            self._check_mixed_auth_targeting(t, server_token_mode)
            self._check_scope_declaration(t)
            self._check_mutate_auth(t)
            self._check_observed_leak(t)

        severity_order = {"HIGH":0, "MEDIUM":1, "LOW":2, "INFO":3}
        findings = sorted(self._findings, key=lambda f: severity_order.get(f.severity, 9))
        hard_fail = any(f.severity == "HIGH" for f in findings)
        return {
            "passed": not hard_fail,
            "server_token_mode": server_token_mode,
            "tool_count": len(tools),
            "findings": [f.to_dict() for f in findings],
            "summary": {
                "HIGH": sum(1 for f in findings if f.severity=="HIGH"),
                "MEDIUM": sum(1 for f in findings if f.severity=="MEDIUM"),
                "LOW": sum(1 for f in findings if f.severity=="LOW"),
                "INFO": sum(1 for f in findings if f.severity=="INFO"),
            },
        }

    # ------------------------------------------------------------- rule checks
    def _check_scheme_validity(self, t: ToolAuth) -> None:
        if t.declared_scheme.lower() not in KNOWN_SCHEMES:
            self._findings.append(AuditFinding(
                "HIGH", "UNKNOWN_SCHEME",
                f"Tool '{t.name}' declares unsupported auth scheme "
                f"'{t.declared_scheme}' (not in {sorted(KNOWN_SCHEMES)}).", t.name))

    def _check_mixed_auth_targeting(self, t: ToolAuth, mode: str) -> None:
        # In a mixed-auth (multi) server, a tool must not declare a scheme the
        # server doesn't also accept — that's a targeting hole. But if the tool
        # declares 'none' while the server is multi-auth globbed, HIGH.
        if mode != "multi":
            return
        s = t.declared_scheme.lower()
        if s == "none":
            self._findings.append(AuditFinding(
                "HIGH", "NO_AUTH_EXPOSED",
                f"Tool '{t.name}' declares no auth in a mixed-auth server — any "
                f"weak token from another tool could invoke it.", t.name))
        if t.observed_schemes and s not in [x.lower() for x in t.observed_schemes]:
            self._findings.append(AuditFinding(
                "MEDIUM", "SCHEME_MISMATCH",
                f"Tool '{t.name}' declares '{s}' but server is observed accepting "
                f"{t.observed_schemes} — targeting hole (may run with wrong/weaker "
                f"credential).", t.name))

    def _check_scope_declaration(self, t: ToolAuth) -> None:
        # OAuth2/mixed tools that mutate must declare scopes; missing scope =
        # open to any token.
        if t.declared_scheme.lower() in ("oauth2", "jwt") and t.permits_mutate \
                and not t.declared_scopes:
            self._findings.append(AuditFinding(
                "MEDIUM", "MISSING_SCOPE",
                f"Mutating OAuth2/JWT tool '{t.name}' declares no scopes — any "
                f"authorized token can call it.", t.name))

    def _check_mutate_auth(self, t: ToolAuth) -> None:
        if t.permits_mutate and t.declared_scheme.lower() in ("none", "anonymous"):
            self._findings.append(AuditFinding(
                "HIGH", "MUTATE_NO_AUTH",
                f"Mutating tool '{t.name}' allows anonymous/no-auth calls.", t.name))

    def _check_observed_leak(self, t: ToolAuth) -> None:
        # If the server observed-accepts strictly MORE schemes than the tool
        # declares for a mutating tool, that's a potential credential-leak path.
        if not t.observed_schemes or not t.permits_mutate:
            return
        declared = set([t.declared_scheme.lower()])
        observed = set(x.lower() for x in t.observed_schemes)
        if observed - declared:
            self._findings.append(AuditFinding(
                "LOW", "OBSERVED_AUTH_LEAK",
                f"Mutating tool '{t.name}' observes auth schemes "
                f"{sorted(observed-declared)} beyond its declared '{t.declared_scheme}' "
                f"— tokens accepted outside declared contract.", t.name))

    # ------------------------------------------------------------- inference
    @staticmethod
    def infer_tool_auth(name: str, description: str,
                        declared_scheme: Optional[str] = None,
                        declared_scopes: Optional[List[str]] = None,
                        permits_mutate: Optional[bool] = None,
                        observed_schemes: Optional[List[str]] = None) -> ToolAuth:
        """Build a ToolAuth from a tool description, inferring mutate-ness from
        the description text (deterministic verb detection) when not given."""
        desc = (description or "").lower()
        write_verbs = ("write", "create", "update", "delete", "remove", "add",
                       "set", "post", "put", "patch", "mutate", "insert",
                       "reset", "execute", "run", "invoke", "trigger")
        if permits_mutate is None:
            permits_mutate = bool(re.search(r"\b(" + "|".join(write_verbs) + r")\b", desc))
        return ToolAuth(
            name=name,
            declared_scheme=(declared_scheme or "bearer"),
            declared_scopes=list(declared_scopes or []),
            observed_schemes=[s.lower() for s in (observed_schemes or [])],
            permits_mutate=permits_mutate,
        )


# ------------------------------------------------------------------ MCP surface
def register_auth_audit_tools(mcp) -> None:
    auditor = MixedAuthAuditor()

    @mcp.tool()
    def audit_server_auth(tools: List[Dict[str, Any]],
                          server_token_mode: str = "auto") -> Dict[str, Any]:
        """Audit a mixed-auth MCP server's declared security model.

        tools: [{name, description, declared_scheme?, declared_scopes?[],
                 permits_mutate?, observed_schemes?[]}]
        Runs deterministic checks: valid scheme, no-auth-exposed-in-mixed,
        scheme-mismatch targeting holes, missing scopes on mutating OAuth2,
        anonymous mutation, observed-auth leak. Returns PASS/FAIL + findings.
        """
        parsed = [MixedAuthAuditor.infer_tool_auth(t.get("name",""), t.get("description",""),
                    t.get("declared_scheme"), t.get("declared_scopes"),
                    t.get("permits_mutate"), t.get("observed_schemes"))
                  for t in tools]
        return auditor.audit(parsed, server_token_mode)

    @mcp.tool()
    def audit_token_mode(declared_schemes: List[str],
                         observed_schemes: List[str]) -> Dict[str, Any]:
        """Given the schemes a server declares vs observes, report whether it is
        single- or mixed-auth and whether the observed set matches the declared
        (a mismatch = tools may inherit a scheme they don't declare)."""
        declared = set(s.lower() for s in declared_schemes)
        observed = set(s.lower() for s in observed_schemes)
        mode = "multi" if len(declared) > 1 else "single"
        unmatched = sorted(observed - declared)
        return {
            "inferred_mode": mode,
            "declared": sorted(declared),
            "observed": sorted(observed),
            "observed_not_declared": unmatched,
            "warning": (f"{len(unmatched)} observed scheme(s) not declared — "
                        "tools may inherit them silently" if unmatched else None),
        }


def demo_tools() -> List[ToolAuth]:
    """Example: a mixed-auth server where the filesystem tool is Bearer-only
    but the server also accepts OAuth, and a 'reset' tool has no auth."""
    return [
        MixedAuthAuditor.infer_tool_auth("read_file", "read a file", "bearer", permits_mutate=False),
        MixedAuthAuditor.infer_tool_auth("write_file", "write a file", "bearer", permits_mutate=True),
        MixedAuthAuditor.infer_tool_auth("reset_offsets", "reset the connector offsets", "none", permits_mutate=True),
        MixedAuthAuditor.infer_tool_auth(
            "create_token", "issue a new access token", "oauth2",
            declared_scopes=["admin"], permits_mutate=True,
            observed_schemes=["oauth2", "bearer"]),
    ]


if __name__ == "__main__":
    # deterministic self-check
    a = MixedAuthAuditor()
    res = a.audit(demo_tools(), "auto")
    print(json.dumps(res, indent=2))
    print("\nverdict:", "PASS" if res["passed"] else "FAIL (HIGH findings present)")
