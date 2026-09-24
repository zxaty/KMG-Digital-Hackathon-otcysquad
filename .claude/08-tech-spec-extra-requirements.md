# 08. Tech-Spec extra requirements — category taxonomy for additional_findings

**Status: reconstructed, not authoritative.** This file did not exist
anywhere in the repository before this commit — `.claude/01` through
`07` and `AGENTS.md` were the only numbered docs present. The category
taxonomy below was supplied directly by the user in conversation while
implementing `agent/tech_spec_findings.py`; the specific detection
criteria for each category beyond the three already implemented are
this agent's best-effort inference, not a transcription of an organizer
document. If an authoritative Tech Spec / ТЗ section for this taxonomy
exists, this file should be regenerated from it and this status line
removed.

## Purpose

`docs/04-report-schema.md`'s `additional_findings` field holds
Tech-Spec-only defects — real problems worth reporting that are outside
the 8 mandatory IB-01..08 requirements and therefore must never block
the pipeline (§4.8.1). Each entry needs a `category`, so findings can be
grouped/triaged without inventing a new taxonomy per finding. This doc
is that taxonomy's home.

## Categories

| Category | Scope (best-effort description) |
|---|---|
| `access-control-detail` | Endpoint/role-check nuances that are real but don't rise to (or aren't in scope of) IB-01's admin-function definition — e.g. a non-admin write endpoint with a looser-than-expected permission check. |
| `session-auth-detail` | Authentication/session-lifecycle robustness that isn't IB-02's core "is every request checked" question — throttling, password policy strength, token/session revocation on credential change. **All three currently-implemented deterministic findings live here.** |
| `data-handling-detail` | Data storage/handling nuances outside IB-04's specific PII-encryption-and-password-hashing scope — e.g. retention, validation, or data-shape issues. |
| `audit-detail` | Logging/audit-trail nuances outside IB-07's cross-cutting coverage question — e.g. log verbosity, retention, or format issues that aren't a coverage gap. |
| `export-detail` | Export/download-endpoint nuances outside IB-08's specific role-check-and-audit-write definition — e.g. export format, rate-limiting, or content issues. |
| `transport-detail` | Transport-security nuances outside IB-03's TLS-version/cipher-suite scope — e.g. header hardening, redirect edge cases. |
| `channel-detail` | Nuances in non-HTTP communication channels (email, background workers, inter-process) that don't map cleanly onto any of the 8 IB requirements. |
| `documentation-detail` | Documentation completeness/accuracy issues outside IB-06's specific six-regulatory-reference requirement. |

## Currently implemented (agent/tech_spec_findings.py — fully deterministic, no LLM call)

All three below are classified `session-auth-detail`, since each is
about the robustness of the authentication/session layer rather than
endpoint access control, data storage, audit coverage, export, transport,
or documentation:

1. **No failed-login throttling (Tech Spec §4.4.6).** Deterministic:
   `login_throttling.throttling_mechanism_found` in `index.json`
   already resolves this from an exhaustive `INSTALLED_APPS`/`MIDDLEWARE`
   search. See `agent/tech_spec_findings.py::find_missing_login_throttling`.
2. **Incomplete `AUTH_PASSWORD_VALIDATORS` coverage (Tech Spec §4.4.8).**
   Deterministic: `password_validators.covers_*` booleans in `index.json`.
   See `find_incomplete_password_validators`.
3. **No token/session revocation on role or password change (Tech Spec
   §4.4.7).** Deterministic: `token_lifecycle.role_or_password_change_functions[].revocation_related_calls`
   in `index.json`. See `find_missing_token_revocation`.

## Open items

Everything else is unresolved pending the real organizer source:

- Concrete detection criteria for `access-control-detail`,
  `data-handling-detail`, `audit-detail`, `export-detail`,
  `transport-detail`, `channel-detail`, `documentation-detail` — which
  specific Tech Spec sections map to each, and whether any of them are
  as fully deterministic as the three `session-auth-detail` items above,
  or genuinely require LLM judgment (in which case they'd need their own
  evidence-bundle-and-prompt path, analogous to `agent/analyzer.py`, not
  `agent/tech_spec_findings.py`'s zero-LLM contract).
- Whether the three implemented `session-auth-detail` findings are
  correctly categorized at all — this agent inferred the mapping from
  the category name alone, not from a source document defining it.
- Severity guidance, if any, for `additional_findings` entries (the
  current implementation omits severity entirely, since §4.8.1 says
  these never affect the exit-code decision either way).
