"""Per-requirement LLM analysis (IB-check agent, module 3).

Design (see the accompanying conversation for the full rationale):

- One LLM call per IB requirement, not per finding-candidate. Module 2
  (agent/indexer.py) already enumerates every candidate deterministically
  and attaches labeled file+line evidence to it; the model's job is to
  JUDGE that pre-assembled evidence, not to search the codebase. That
  collapses what would otherwise be dozens of tiny per-route/per-model
  calls into 8 calls total, which matters directly for the 30-minute
  wall-clock budget in docs/05-agent-architecture.md.

- The model never states its own `requirement_id`, `requirement_text`,
  or `evidence` text. Those are stamped on by this module from a fixed
  table (matching docs/02-ib-requirements.md's own wording) and by
  re-reading the real source file at the location the model reports -
  never generated or transcribed by the model itself. This guarantees
  the code snippet in the final report is always byte-exact truth, and
  removes any risk of the model paraphrasing the requirement text
  inconsistently between calls.

- "No real file+line location -> doesn't count" (TZ Sec.4.6.4) is enforced
  mechanically here, not left to the model to remember: every violation
  the model reports must resolve to a (file, line) pair that was
  actually present in the evidence bundle sent to it for that call. A
  violation that fails this (missing location, hallucinated location,
  bad severity value) is dropped and logged as rejected, never silently
  kept or silently promoted to a false "pass".

Known current limitation, stated up front rather than discovered later:
no LLM API credentials or SDK are available in this development
environment (checked: no ANTHROPIC_API_KEY-shaped env var, `anthropic`
package not installed). Everything in this module except the actual
network call has been exercised against a real project via
MockLLMClient (see agent/tests/test_analyzer.py) - the AnthropicClient
class is written to the real API shape but has not been run against the
live API. That is the one part of module 3 not yet proven end-to-end.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")
DEFAULT_SEVERITY = "medium"


# ---------------------------------------------------------------------------
# Requirement table - text stamped onto every finding, never model-generated
# ---------------------------------------------------------------------------

IB_REQUIREMENTS: dict[str, str] = {
    "IB-01": "Admin functionality (user/role/permission/system-settings/export management) must be "
             "restricted to the 'administrator' role, enforced server-side on every request; "
             "client-side hiding does not satisfy this requirement.",
    "IB-02": "Session or token validity must be checked server-side on every request to a protected "
             "endpoint, including API endpoints.",
    "IB-03": "Client-server traffic must be protected in transit via TLS 1.2 or higher with strong "
             "cipher suites only; configuration allowing plaintext or weak/old TLS is a violation.",
    "IB-04": "Personal data (full name, login, email, password) must be stored per СТ РК 1073-2007 "
             "cryptographic protection level; passwords specifically must use only bcrypt/argon2/scrypt, "
             "never plaintext or a fast general-purpose hash without an adaptive KDF.",
    "IB-05": "Local application logs must be encrypted at rest and protected from tampering by a normal "
             "OS user before being sent to the server.",
    "IB-06": "Project documentation (README/ТЗ) must reference: the Law on Cybersecurity "
             "(24.11.2015 №418-V), the Law on Personal Data (21.05.2013 №94-V), Government resolution "
             "№832 (20.12.2016), СТ РК ISO/IEC 27001-2023, СТ РК ISO/IEC 27002-2023, and СТ РК 1073-2007.",
    "IB-07": "A single, unified user-action log and DB-event log must cover the whole project (all "
             "data-mutating models/entities and all login/logout/failed-login events), not just part "
             "of it.",
    "IB-08": "PII exports must be restricted to the 'administrator' role and every export must be "
             "recorded in the audit log; both the role check and the audit-log write are required "
             "independently for every export endpoint.",
}


# ---------------------------------------------------------------------------
# LLM client abstraction - swappable, so the validation pipeline is testable
# without any network access or credentials.
# ---------------------------------------------------------------------------

class LLMClient(Protocol):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Return the raw text response for a single-turn completion."""
        ...


@dataclass
class MockLLMClient:
    """Returns a pre-scripted response. Used in tests to prove the
    evidence-bundling and validation pipeline works without a real API."""
    scripted_response: str

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return self.scripted_response


class AnthropicClient:
    """Real client, written to the current Messages API shape. NOT run
    against the live API in this environment - no credentials or SDK
    are available here (see module docstring). Wiring this up when a
    key exists should only require `pip install anthropic` and setting
    ANTHROPIC_API_KEY; no other code in this module changes.
    """

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None, max_tokens: int = 4096):
        import os
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError(
                "anthropic package is not installed. Run: pip install anthropic"
            ) from exc
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY not set and no api_key passed")
        self._client = anthropic.Anthropic(api_key=key)
        self.model = model
        self.max_tokens = max_tokens

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


# ---------------------------------------------------------------------------
# Evidence-bundle builders - one per requirement. Each selects curated
# top-level index.json fields (never the whole index) plus, where doing
# so doesn't risk hiding the very thing the model needs to judge, a
# filtered subset of rows (as IB-07 already does for bulk_orm_calls).
#
# IB-01/IB-02 deliberately do NOT pre-filter the route list to a
# "looks admin-y" / "looks protected" subset: deciding WHICH routes
# constitute admin functionality (IB-01) or a protected endpoint (IB-02)
# is itself part of what the model must judge. Pre-filtering by name
# risks silently dropping the one route a target project renamed.
# IB-08 is the exception - docs/02 gives an unambiguous, checkable
# definition ("every export/download endpoint... that returns PII"), so
# filtering routes by that specific pattern is a curation decision, not
# a guess.
# ---------------------------------------------------------------------------

def _slim_route(r: dict, keys: tuple[str, ...]) -> dict:
    return {k: r.get(k) for k in keys}


_ROUTE_KEYS_FOR_GUARD_ANALYSIS = (
    "pattern", "name", "view_module", "view_function", "view_file", "view_line",
    "url_level_wrappers", "decorators", "body_guard_calls",
)


def build_evidence_ib01(index: dict) -> dict:
    """IB-01: admin-function access control. Full route list (see module
    note above on why routes aren't pre-filtered) plus guard_definitions
    (the real body of every project-local guard referenced anywhere -
    without this the model would only see decorator NAMES, not whether
    a given guard checks role=='administrator' or something weaker like
    is_staff) plus INSTALLED_APPS for the built-in admin-panel check.
    """
    routes = [_slim_route(r, _ROUTE_KEYS_FOR_GUARD_ANALYSIS) for r in index.get("routes", [])]
    return {
        "routes": routes,
        "guard_definitions": index.get("guard_definitions", {}),
        "installed_apps": index.get("settings", {}).get("INSTALLED_APPS", {}).get("value"),
    }


def build_evidence_ib02(index: dict) -> dict:
    """IB-02: server-side session/token validation on every request,
    including APIs. Full route list (same reasoning as IB-01) plus the
    full token_lifecycle bundle for the custom Bearer-token scheme, plus
    MIDDLEWARE to confirm AuthenticationMiddleware is actually wired in
    project-wide rather than assumed.
    """
    routes = [_slim_route(r, _ROUTE_KEYS_FOR_GUARD_ANALYSIS) for r in index.get("routes", [])]
    return {
        "routes": routes,
        "token_lifecycle": index.get("token_lifecycle", {}),
        "middleware": index.get("settings", {}).get("MIDDLEWARE", {}).get("value"),
    }


def build_evidence_ib03(index: dict) -> dict:
    """IB-03: transport security. Config-only requirement, no routes or
    models needed. Pulls only the specific settings.py flags this
    requirement bears on (not the whole settings dict, which also has
    unrelated things like AUTH_PASSWORD_VALIDATORS) plus the full
    auxiliary_configs (proxy.json), since this project's actual
    TLS/redirect behavior is split across both files - settings.py
    alone would be a misleadingly incomplete picture.
    """
    keys = (
        "SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SECURE_SSL_REDIRECT",
        "SECURE_HSTS_SECONDS", "SECURE_PROXY_SSL_HEADER", "SECURE_CONTENT_TYPE_NOSNIFF",
    )
    settings = index.get("settings", {})
    return {
        "relevant_settings": {k: settings[k] for k in keys if k in settings},
        "auxiliary_configs": index.get("auxiliary_configs", {}),
    }


def build_evidence_ib04(index: dict) -> dict:
    """IB-04: crypto protection of PII at rest. PASSWORD_HASHERS for the
    password half; models[] filtered down to ONLY the PII-flagged fields
    of each model (the non-PII fields of e.g. Ticket are noise for this
    requirement specifically) for the storage half; password_bypass_writes
    for the "legacy path bypasses hashing" detect target docs/02 names
    explicitly.
    """
    pii_models = []
    for m in index.get("models", []):
        pii_fields = [f for f in m.get("fields", []) if f.get("pii_name_hint")]
        if pii_fields:
            pii_models.append({
                "app_dir": m["app_dir"], "file": m["file"], "class_name": m["class_name"],
                "line": m["line"], "pii_fields": pii_fields,
            })
    return {
        "password_hashers": index.get("settings", {}).get("PASSWORD_HASHERS", {}),
        "pii_flagged_model_fields": pii_models,
        "password_bypass_writes": index.get("password_bypass_writes", []),
    }


def build_evidence_ib05(index: dict) -> dict:
    """IB-05: local log protection. log_protection{} already contains
    everything needed (local_acl_configure_calls + audit_functions);
    nothing else in the index bears on this requirement, so this is the
    one builder that's a straight pass-through of a single section.
    """
    return {"log_protection": index.get("log_protection", {})}


def build_evidence_ib06(index: dict) -> dict:
    """IB-06: regulatory references in docs. regulatory_references{} is
    already a fully-resolved deterministic result (line-level evidence
    per reference, computed by agent/indexer.py, not by this module) -
    there is arguably little left for the model to judge here beyond
    confirming it, but it still goes through the same call-per-requirement
    path so every requirement gets a requirements_status entry produced
    the same, auditable way.
    """
    return {"regulatory_references": index.get("regulatory_references", {})}


def build_evidence_ib08(index: dict) -> dict:
    """IB-08: PII export control. Unlike IB-01/02, docs/02 gives an
    unambiguous, checkable definition here ("every export/download
    endpoint... that returns PII"), so filtering routes to ones whose
    view function or URL pattern contains export/download/print is a
    curation decision grounded in the requirement's own wording, not a
    guess that risks hiding the target route. Includes decorators,
    body_guard_calls, AND audit_calls together so the model can judge
    the role check and the audit-log write independently, per route, as
    IB-08 explicitly requires (one without the other is still a
    violation).
    """
    hints = ("export", "download", "print")
    keys = ("pattern", "view_function", "view_file", "view_line", "decorators", "body_guard_calls", "audit_calls")
    routes = []
    for r in index.get("routes", []):
        name_blob = f"{r.get('view_function','')} {r.get('pattern','')}".lower()
        if any(h in name_blob for h in hints):
            routes.append(_slim_route(r, keys))
    return {
        "export_like_routes": routes,
        "guard_definitions": index.get("guard_definitions", {}),
    }


def build_evidence_ib07(index: dict) -> dict:
    """IB-07: unified user-action + DB-event log, whole project.

    Deliberately pre-filters bulk_orm_calls to only the
    `looks_like_queryset: true` candidates (3 of 16 in this project) -
    the other 13 are non-ORM `.update()` calls (dict/context/kwargs)
    that would only waste tokens and risk distracting the model from
    the real candidates.
    """
    bulk_candidates = [h for h in index.get("bulk_orm_calls", []) if h.get("looks_like_queryset")]
    coverage = index.get("model_audit_coverage", [])
    uncovered = [m for m in coverage if not m.get("covered_by_post_save_post_delete_signals")]
    return {
        "signal_connections": index.get("signal_wiring", {}).get("connections", []),
        "handler_app_label_filters": index.get("signal_wiring", {}).get("handler_app_label_filters", {}),
        "model_count_total": len(coverage),
        "model_count_uncovered": len(uncovered),
        "uncovered_models": uncovered,
        "bulk_orm_bypass_candidates": bulk_candidates,
    }


EVIDENCE_BUILDERS = {
    "IB-01": build_evidence_ib01,
    "IB-02": build_evidence_ib02,
    "IB-03": build_evidence_ib03,
    "IB-04": build_evidence_ib04,
    "IB-05": build_evidence_ib05,
    "IB-06": build_evidence_ib06,
    "IB-07": build_evidence_ib07,
    "IB-08": build_evidence_ib08,
}


def collect_known_locations(evidence: dict) -> set[tuple[str, int]]:
    """Every (file, line) pair present anywhere in the evidence bundle -
    the allowlist a model-reported violation location must belong to."""
    found: set[tuple[str, int]] = set()

    def walk(obj):
        if isinstance(obj, dict):
            if "file" in obj and "line" in obj and isinstance(obj.get("line"), int):
                found.add((obj["file"], obj["line"]))
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(evidence)
    return found


# ---------------------------------------------------------------------------
# Prompting
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an information-security compliance analyst reviewing a Django \
project against one mandatory security requirement at a time. You are given pre-extracted, \
structured evidence about the project - you do not have access to the rest of the codebase, \
and you must not assume anything about files not shown to you.

Rules, all mandatory:
1. Base your judgment ONLY on the evidence provided below. Do not invent file paths, line \
numbers, or code that is not present in the evidence.
2. Every violation you report MUST reference a (file, line) pair that appears somewhere in \
the evidence provided. If you believe something is wrong but cannot point to a specific \
location already present in the evidence, do not report it as a violation - explain it in \
`summary` instead, or set status to "insufficient_data" with a reason.
3. Do not restate the requirement text or invent a requirement ID - that is added separately.
4. Do not write a code snippet yourself - only report the location; the exact snippet will \
be extracted independently from the real source file.
5. Respond with ONLY a single JSON object matching the schema below. No prose outside the \
JSON, no markdown code fences.

Output schema:
{
  "status": "pass" | "violation" | "insufficient_data",
  "summary": "one or two sentences, the overall verdict for this requirement",
  "violations": [
    {
      "location": {"file": "<exact file path from the evidence>", "line": <exact line number from the evidence>, "function": "<function/class name if known, else null>"},
      "justification": "<precisely what is non-compliant and why, referencing the evidence>",
      "severity": "critical" | "high" | "medium" | "low",
      "recommendation": "<concrete fix>"
    }
  ],
  "insufficient_data_reason": null or "<why you could not reach pass/violation>"
}"""


def build_user_prompt(requirement_id: str, requirement_text: str, evidence: dict) -> str:
    return (
        f"Requirement {requirement_id}: {requirement_text}\n\n"
        "Evidence (structured, extracted deterministically from the project - "
        "file/line locations here are the ONLY ones you may cite):\n"
        f"{json.dumps(evidence, indent=2, ensure_ascii=False)}\n\n"
        "Return the JSON object described in the system prompt now."
    )


# ---------------------------------------------------------------------------
# Response parsing & validation
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    location: dict
    justification: str
    severity: str
    recommendation: str
    evidence_snippet: str


@dataclass
class RejectedCandidate:
    raw: dict
    reason: str


@dataclass
class AnalysisResult:
    requirement_id: str
    requirement_text: str
    status: str  # "pass" | "violation" | "insufficient_data"
    summary: str
    violations: list[Violation] = field(default_factory=list)
    rejected: list[RejectedCandidate] = field(default_factory=list)
    insufficient_data_reason: str | None = None
    raw_model_output: str = ""
    parse_error: str | None = None


def extract_snippet(project_root: Path, file: str, line: int, context: int = 0) -> str | None:
    """Read the real source at (file, line) - never trust the model's own
    transcription of a code/config snippet."""
    path = project_root / file
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    if not (1 <= line <= len(lines)):
        return None
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    return "\n".join(lines[start:end])


def analyze_ib06_deterministic(index: dict) -> AnalysisResult:
    """IB-06 needs no LLM call: build_evidence_ib06's entire bundle is
    already just regulatory_references, a fully-resolved deterministic
    result computed by agent/indexer.py::index_regulatory_references
    (line-level evidence per reference, not a bare boolean). There is no
    remaining judgment call for a model to make - the evidence already
    IS the verdict. Mirrors analyze_requirement's contract (same
    AnalysisResult shape, same IB_REQUIREMENTS text) so callers can
    treat all 8 requirements uniformly, but skips the model entirely:
    no prompt, no JSON parsing, no location-allowlist enforcement,
    because there is no untrusted model output to validate here.
    """
    requirement_text = IB_REQUIREMENTS["IB-06"]
    rr = index.get("regulatory_references", {})
    reference_found = rr.get("reference_found", {})
    reference_evidence = rr.get("reference_evidence", {})
    searched_files = rr.get("searched_files", [])

    if rr.get("all_six_present"):
        return AnalysisResult(
            requirement_id="IB-06",
            requirement_text=requirement_text,
            status="pass",
            summary=f"All 6 required regulatory references found in {', '.join(searched_files) or 'the searched docs'}.",
        )

    violations: list[Violation] = []
    for key, found in reference_found.items():
        if found:
            continue
        evidence_list = reference_evidence.get(key, [])
        if evidence_list:
            # found False but evidence present shouldn't normally happen -
            # handle honestly rather than assume, using the real evidence
            first = evidence_list[0]
            location = {"file": first["file"], "line": first["line"], "function": None}
            snippet = first["text"]
        else:
            # a missing reference has no line to point at - it's an
            # absence, not a location - so location degrades honestly to
            # the real file it should have been in, with no fabricated line
            location = {"file": searched_files[0] if searched_files else None, "line": None, "function": None}
            snippet = ""
        violations.append(Violation(
            location=location,
            justification=f"Reference '{key}' was not found in any searched documentation file "
                           f"({', '.join(searched_files) or 'no files were found to search'}).",
            severity="medium",
            recommendation=f"Add an explicit reference to {key.replace('_', ' ')} in the README or "
                            "Tech Spec regulatory-sources section.",
            evidence_snippet=snippet,
        ))

    return AnalysisResult(
        requirement_id="IB-06",
        requirement_text=requirement_text,
        status="violation",
        summary=f"{len(violations)} of 6 required regulatory references missing.",
        violations=violations,
    )


def analyze_requirement(
    requirement_id: str,
    index: dict,
    client: LLMClient,
    project_root: Path,
) -> AnalysisResult:
    if requirement_id not in IB_REQUIREMENTS:
        raise ValueError(f"unknown requirement id {requirement_id!r}")
    if requirement_id not in EVIDENCE_BUILDERS:
        raise NotImplementedError(f"evidence builder for {requirement_id} not implemented yet")

    requirement_text = IB_REQUIREMENTS[requirement_id]
    evidence = EVIDENCE_BUILDERS[requirement_id](index)
    known_locations = collect_known_locations(evidence)

    user_prompt = build_user_prompt(requirement_id, requirement_text, evidence)
    raw = client.complete(SYSTEM_PROMPT, user_prompt)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return AnalysisResult(
            requirement_id=requirement_id,
            requirement_text=requirement_text,
            status="insufficient_data",
            summary="",
            insufficient_data_reason=f"model response was not valid JSON: {exc}",
            raw_model_output=raw,
            parse_error=str(exc),
        )

    claimed_status = parsed.get("status")
    summary = parsed.get("summary", "")
    raw_violations = parsed.get("violations") or []

    kept: list[Violation] = []
    rejected: list[RejectedCandidate] = []

    for v in raw_violations:
        loc = v.get("location") if isinstance(v, dict) else None
        file = loc.get("file") if isinstance(loc, dict) else None
        line = loc.get("line") if isinstance(loc, dict) else None

        if not file or not isinstance(line, int):
            rejected.append(RejectedCandidate(v, "missing or malformed location (file/line required)"))
            continue
        if (file, line) not in known_locations:
            rejected.append(RejectedCandidate(v, f"location ({file}:{line}) was not present in the evidence given to the model - likely hallucinated"))
            continue
        snippet = extract_snippet(project_root, file, line)
        if snippet is None:
            rejected.append(RejectedCandidate(v, f"location ({file}:{line}) does not resolve to a real, readable line in the project"))
            continue

        severity = v.get("severity")
        if severity not in ALLOWED_SEVERITIES:
            severity = DEFAULT_SEVERITY  # clamp, don't drop the whole finding over this alone

        kept.append(Violation(
            location=loc,
            justification=v.get("justification", ""),
            severity=severity,
            recommendation=v.get("recommendation", ""),
            evidence_snippet=snippet,
        ))

    # Reconcile status: never silently report "pass" if the model raised
    # something, and never keep "violation" status with zero grounded findings.
    # Both sub-cases of "claimed violation but nothing survived" must land
    # here, not just the "some candidates got rejected" one - a model that
    # claims status="violation" while listing zero items at all previously
    # fell through to the final `else` and became a silent false "pass"
    # (caught by manual review of this branch, not by the original tests).
    if kept:
        final_status = "violation"
        insufficient_reason = None
    elif claimed_status == "violation":
        final_status = "insufficient_data"
        if rejected:
            insufficient_reason = (
                f"model reported {len(rejected)} violation(s) for {requirement_id} but none had a "
                "location that could be grounded in the evidence provided - see rejected candidates"
            )
        else:
            insufficient_reason = (
                f"model reported status=\"violation\" for {requirement_id} but the violations list was empty"
            )
    elif claimed_status == "insufficient_data":
        final_status = "insufficient_data"
        insufficient_reason = parsed.get("insufficient_data_reason") or "model reported insufficient_data with no reason given"
    else:
        final_status = "pass"
        insufficient_reason = None

    return AnalysisResult(
        requirement_id=requirement_id,
        requirement_text=requirement_text,
        status=final_status,
        summary=summary,
        violations=kept,
        rejected=rejected,
        insufficient_data_reason=insufficient_reason,
        raw_model_output=raw,
    )
