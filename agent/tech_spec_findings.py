"""Deterministic Tech-Spec-only findings -> report.json's additional_findings.

Scope: this module handles ONLY findings that are already 100% resolved
facts in index.json (module 2's output) - no LLM call, no hallucination
surface, because there is nothing left to judge. As of now that's three
checks, all confirmed fully deterministic on the same reasoning already
applied to IB-06 in agent/analyzer.py:

  - no failed-login throttling (Tech Spec Sec.4.4.6)
  - incomplete AUTH_PASSWORD_VALIDATORS coverage (Tech Spec Sec.4.4.8)
  - no token/session revocation on role or password change (Sec.4.4.7)

This is NOT meant to be the only path into additional_findings forever.
Tech-Spec items that genuinely require judgment (once docs/08's other
"Open items" are resolved) belong in a separate LLM-backed path later,
analogous to agent/analyzer.py's per-requirement calls - they should NOT
be forced into this module just because they also produce
additional_findings entries. This module's contract is specifically
"deterministic, zero-LLM, from index.json alone."

Category taxonomy used below (access-control-detail, session-auth-detail,
data-handling-detail, audit-detail, export-detail, transport-detail,
channel-detail, documentation-detail) was supplied directly by the user
in conversation - docs/08-tech-spec-extra-requirements.md, which is
supposed to be the source of this taxonomy, does not exist anywhere in
this repository (checked: only .claude/01 through 07 and AGENTS.md are
present). All three checks below are classified as "session-auth-detail"
since each is about the robustness of the authentication/session layer
(throttling failed logins, password policy strength, token lifecycle on
credential change) rather than endpoint-level access control, PII
storage/export, audit logging, transport, or documentation - but this
classification could not be cross-checked against the actual taxonomy
document and should be verified against it once it exists.

Location honesty rule, per the user's explicit instruction: never invent
a file/line. Where a finding is genuinely about a whole settings list
(no single line "is" the bug), the location points at the real line of
the specific settings assignment in question (e.g. INSTALLED_APPS's own
line, AUTH_PASSWORD_VALIDATORS's own line) - never a fabricated line
number, and resolved by checking the filesystem, not just string-pasting
a dotted module name into a path.
"""
from __future__ import annotations

from pathlib import Path


def _resolve_module_file(index: dict, dotted: str) -> str | None:
    """Best-effort real relative file path for a dotted module name,
    using index['meta']['search_roots'] (already computed, absolute, by
    Indexer) and index['meta']['root']. Returns None rather than a
    fabricated path if the file can't be confirmed to exist on disk -
    callers must handle that case honestly (see below), not paper over it.
    """
    if not dotted:
        return None
    project_root = index.get("meta", {}).get("root")
    search_roots = index.get("meta", {}).get("search_roots") or []
    if not project_root:
        return None
    root_path = Path(project_root)
    parts = dotted.split(".")
    for base in search_roots:
        base_path = Path(base)
        candidate = base_path.joinpath(*parts)
        for p in (candidate.with_suffix(".py"), candidate / "__init__.py"):
            if p.is_file():
                try:
                    return str(p.relative_to(root_path))
                except ValueError:
                    return str(p)
    return None


def _settings_location(index: dict, settings_key: str) -> dict:
    """Location for a specific settings.py assignment (e.g. INSTALLED_APPS),
    honestly degrading to {"file": <dotted module name>, "line": None} if
    the real file can't be confirmed on disk - never a fabricated line."""
    settings_module = index.get("meta", {}).get("settings_module")
    file = _resolve_module_file(index, settings_module) if settings_module else None
    if file is None:
        return {"file": settings_module, "line": None}
    entry = index.get("settings", {}).get(settings_key, {})
    return {"file": file, "line": entry.get("line")}


def find_missing_login_throttling(index: dict) -> list[dict]:
    """Tech Spec Sec.4.4.6. Fully resolved by index.json's own
    login_throttling.throttling_mechanism_found - see
    agent/indexer.py::index_login_throttling, which already searched the
    complete INSTALLED_APPS/MIDDLEWARE lists exhaustively."""
    lt = index.get("login_throttling", {})
    if lt.get("throttling_mechanism_found"):
        return []
    apps = lt.get("searched_installed_apps", [])
    middleware = lt.get("searched_middleware", [])
    description = (
        "No failed-login throttling/lockout mechanism found (Tech Spec Sec.4.4.6). "
        f"Searched all {len(apps)} INSTALLED_APPS entries and all {len(middleware)} MIDDLEWARE "
        "entries for anything matching axes/ratelimit/defender/lockout/throttl/brute - none "
        "present. Add a rate-limiting/lockout mechanism (e.g. django-axes) or equivalent."
    )
    return [{
        "category": "session-auth-detail",
        "description": description,
        "location": _settings_location(index, "INSTALLED_APPS"),
    }]


def find_incomplete_password_validators(index: dict) -> list[dict]:
    """Tech Spec Sec.4.4.8. Fully resolved by index.json's own
    password_validators.covers_* booleans - see
    agent/indexer.py::index_password_validators. All three missing
    behaviors share one real location (the single AUTH_PASSWORD_VALIDATORS
    assignment), so this is one combined finding, not three duplicate
    ones pointing at the identical line."""
    pv = index.get("password_validators", {})
    missing = []
    if not pv.get("covers_common_password_rejection"):
        missing.append("rejection of common/well-known passwords")
    if not pv.get("covers_all_numeric_rejection"):
        missing.append("rejection of all-numeric passwords")
    if not pv.get("covers_password_reuse_block"):
        missing.append("blocking reuse of a previous password")
    if not missing:
        return []
    configured = ", ".join(pv.get("configured_validators", [])) or "none"
    description = (
        "AUTH_PASSWORD_VALIDATORS does not cover all password-policy behaviors required by "
        f"Tech Spec Sec.4.4.8: missing {', '.join(missing)}. Currently configured: {configured}."
    )
    return [{
        "category": "session-auth-detail",
        "description": description,
        "location": _settings_location(index, "AUTH_PASSWORD_VALIDATORS"),
    }]


def find_missing_token_revocation(index: dict) -> list[dict]:
    """Tech Spec Sec.4.4.7. Fully resolved by index.json's own
    token_lifecycle.role_or_password_change_functions[].revocation_related_calls
    - see agent/indexer.py::index_token_lifecycle. One finding per
    function (change_role, reset_password, ...) since each is a distinct,
    real (file, line) location - never merged into one shared/fabricated
    location."""
    findings = []
    for entry in index.get("token_lifecycle", {}).get("role_or_password_change_functions", []):
        if entry.get("revocation_related_calls"):
            continue
        findings.append({
            "category": "session-auth-detail",
            "description": (
                f"`{entry['function']}` changes a user's role or password but performs no "
                "token/session revocation (Tech Spec Sec.4.4.7) - any previously issued API "
                "token or session for that user remains valid after the change."
            ),
            "location": {"file": entry["file"], "line": entry["line"]},
        })
    return findings


def assemble_tech_spec_findings(index: dict) -> list[dict]:
    """All currently-implemented deterministic Tech-Spec findings, in a
    stable order (throttling, password validators, token revocation)."""
    findings: list[dict] = []
    findings.extend(find_missing_login_throttling(index))
    findings.extend(find_incomplete_password_validators(index))
    findings.extend(find_missing_token_revocation(index))
    return findings
