# 07. Verification protocol — mandatory before claiming "done"

This file exists because of one failure mode: an agent implements
something, doesn't run it, and reports "this works" / "this is fixed"
based on the code *looking* correct. That is not acceptable here. This
protocol is not optional and applies to every unit of work, not just
the final submission.

## Definition of done

A task is "done" only when all of the following are true, with
evidence you actually produced (a command you ran + its real output),
not a description of expected behavior:

1. The code runs to completion (or fails in the exact way the spec
   says it should — e.g. exit 2 on injected model failure).
2. The actual output was inspected against the spec in `04-report-schema.md`
   / `05-agent-architecture.md` — not assumed to match.
3. Exit code matches `report.json.summary.overall_result` per the table
   in `04-report-schema.md`.
4. No step was skipped because "it should be fine."

If any of these can't be shown, the task is **not done** — say so
explicitly, don't round up to "done."

## The loop

```
implement → run → inspect real output → matches spec?
                                          ├─ yes → done, show evidence
                                          └─ no  → diagnose → fix → run again
```

Repeat the loop yourself. Do not stop after one failed attempt and ask
the user "should I keep trying?" — that's your job unless you're
genuinely stuck (see "When to actually ask" below). A single run that
crashes is a bug to fix, not a status to report.

## Minimum test battery for this project

Run these, in order, before saying any part of the agent is working.
Each has a concrete, checkable pass condition — not "looks reasonable."

1. **Smoke test — reference version of the test project (no violations
   expected).**
   - Run the agent end-to-end.
   - Check: exit code == 0, `violations_count == 0`,
     `requirements_status` has all 8 keys set to `pass`.
   - If any requirement shows a violation here → false positive, fix
     the detector before moving on.

2. **Smoke test — version with injected violations (if/when available).**
   - Exit code == 1, `violations_count >= 1`.
   - Every entry in `violations[]` has all required fields non-empty
     (`requirement_id`, `location.file`, `evidence`, `justification`,
     `severity`, `recommendation`) — reject any finding missing a field,
     per §4.6.4 it wouldn't count anyway.

3. **Known fixtures from `03-test-project-map.md` §"Observations."**
   - Point the agent at the public repo copy.
   - Does it flag `export_json` under IB-08? Does it flag `catalog_api`
     under IB-02? These are known-suspect patterns — if the agent
     misses both, the detection logic for those requirements is broken,
     not "mostly working."
   - Does it NOT flag `hashers.py` / `audit.py` as violations (the
     positive examples in the same doc)? If it does, that's a false
     positive to fix.

4. **Report schema validation.**
   - Parse `report.json` with an actual JSON parser, not eyeballing it.
   - Validate required top-level keys exist: `meta`, `summary`,
     `violations`, `additional_findings`, `limitations`.
   - Validate `summary.requirements_status` has exactly 8 keys, one per
     `IB-01`..`IB-08`.

5. **Exit-code ↔ report consistency.**
   - Script this as an actual check: read the process exit code, read
     `report.json.summary.overall_result`, assert they match the table
     in `04-report-schema.md`. Don't just glance at both.

6. **Timeout behavior (§4.7.2).**
   - Simulate/force a timeout condition if feasible; confirm a partial
     report is still written and the exit code reflects findings so
     far, not a crash with no output.

7. **External-failure behavior (§4.7.3).**
   - Simulate the model being unreachable; confirm exit code 2 and no
     report is required (don't treat "no report" as a bug in this one
     case — it's the spec).

8. **No-secrets check on the report itself.**
   - Grep the generated `report.json`/`report.md` for patterns that
     look like real credentials/keys pulled from the target repo's
     config. If found verbatim (not redacted) → bug, fix before
     anything else — this is a hard rule, not a style issue.

9. **CI/CD run.**
   - Actually trigger the GitHub Actions workflow (push to a branch),
     don't just review the YAML. Confirm: artifact uploaded, step
     summary shows exit code + violation count + violated requirement
     list without opening the artifact, pipeline blocked/passed
     correctly.

## Iterating without asking

If a test above fails: diagnose from the actual error/output, fix,
re-run the same test. Keep doing this yourself. Don't ask "want me to
fix this?" — fixing failing tests is the default action, not something
that needs permission.

## When to actually ask instead of continuing alone

Stop and ask only when one of these is true, and say exactly what you
tried:

- You've made several distinct genuine attempts at the same failure and
  it persists — describe what you tried, the actual error each time,
  and your best hypothesis for what's needed.
- The blocker requires something you don't have (a credential, a
  decision the organizer hasn't published yet — e.g. §4.9 constraints —
  a missing test-project version).
- Fixing it would require violating a hard rule in `AGENTS.md` (e.g.
  modifying the target repo, adding an interactive prompt).

Otherwise: keep iterating, and report progress with real evidence, not
reassurance.
