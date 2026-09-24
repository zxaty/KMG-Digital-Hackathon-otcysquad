# 04. Report format (report.json / report.md)

Source: ТЗ §4.6 + "Materials to submit" §1.2. Both formats submitted
together, identical content.

## Required fields per violation (§4.6.2)

- `requirement_id` — e.g. `IB-08`
- `requirement_text` — the violated requirement, stated precisely
- `location` — file path + line number and/or function/class/config
  parameter name
- `evidence` — the code/config snippet that grounds the finding
- `justification` — exactly what's non-compliant and why
- `severity`
- `recommendation` — how to fix

**Hard rule (§4.6.4):** a finding with no concrete location, or with
generic reasoning that doesn't establish the actual mismatch, does
**not** count as a violation to the review committee — it earns nothing
and hurts the accuracy score.

## Summary section (§4.6.3)

- `commit` — test-project commit checked (must match the value reported
  separately per submission checklist item 6)
- `started_at`, `finished_at`, `duration_seconds`
- `overall_result` — **must match** the CI/CD exit code (§4.6.5)
- `violations_count`
- `requirements_status` — status for **all 8** requirements, including
  the ones with no findings (must be explicit "checked, clean", not
  omitted)

## JSON schema

```json
{
  "meta": {
    "commit": "a81f32c...",
    "started_at": "2026-09-24T10:00:00+05:00",
    "finished_at": "2026-09-24T10:14:32+05:00",
    "duration_seconds": 872,
    "agent_version": "1.0.0",
    "model": "provider/model-name"
  },
  "summary": {
    "overall_result": "fail",
    "exit_code": 1,
    "violations_count": 2,
    "requirements_status": {
      "IB-01": "pass", "IB-02": "violation", "IB-03": "pass",
      "IB-04": "pass", "IB-05": "pass", "IB-06": "pass",
      "IB-07": "pass", "IB-08": "violation"
    }
  },
  "violations": [
    {
      "requirement_id": "IB-08",
      "requirement_text": "PII export restricted to administrator role; every export must be audit-logged",
      "location": {"file": "portal/views.py", "line": 123, "function": "export_json"},
      "evidence": "@login_required\n@require_GET\ndef export_json(request): ...",
      "justification": "Returns email/name/role for all users to any authenticated user (no role==administrator check); no audit.record() call",
      "severity": "high",
      "recommendation": "Use access.admin_required instead of login_required; add audit.record('export', 'people:json', count=len(rows))"
    }
  ],
  "additional_findings": [
    {"category": "tech spec / other", "description": "...", "location": {"file": "...", "line": 0}}
  ],
  "limitations": [
    "Files X not analyzed because Y",
    "IB-06 checked against README.md only; docs/*.docx not parsed"
  ]
}
```

Notes:
- `requirements_status` always has all 8 keys, even when clean —
  explicit requirement of §4.6.3.
- `additional_findings` — for Technical Spec defects and other issues
  **outside** IB-01…08 (§4.8.1: don't block the pipeline, but must be
  reported separately).
- `limitations` — required for the completeness score; the committee
  explicitly rewards explicit "checked" vs "insufficient data" calls.
  Empty array is fine; missing field is not.
- **Never** put real secrets in the report (passwords, keys, tokens)
  even when found in target code — redact the value
  (`"password": "***REDACTED***"`), keep the finding.

## report.md structure

```markdown
# IB Security Report

**Commit:** a81f32c
**Started:** 2026-09-24 10:00:00 | **Finished:** 10:14:32 | **Duration:** 14m32s
**Result:** ❌ FAIL (exit 1) — 2 violations

## Requirement status
| ID | Requirement | Status |
|---|---|---|
| IB-01 | Admin access control | ✅ |
| IB-02 | Session/token check | ❌ 1 violation |
| ... | ... | ... |

## Violations

### IB-08 — PII export control [HIGH]
**Where:** `portal/views.py`, `export_json` (line 123)
​```python
@login_required
@require_GET
def export_json(request): ...
​```
**Why:** ...
**Fix:** ...

## Additional findings (outside IB scope)
...

## Analysis limitations
...
```

## Report ↔ exit code consistency (§4.6.5, hard rule)

| exit code | overall_result | violations_count |
|---|---|---|
| 0 | pass | 0 |
| 1 | fail | ≥1 |
| 2 | error (partial/no report — see `05-agent-architecture.md`) | — |

A mismatch here directly hurts the "report quality — consistency with
pipeline decision" score.
