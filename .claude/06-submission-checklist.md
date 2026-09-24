# 06. Submission checklist

Source: "Materials to submit" doc from the organizer. Submit **no later
than 1 hour before the defense**, as one archive or a shared folder link
accessible to the review committee. Materials submitted after the
defense starts **are not accepted**. Missing item → **state it
explicitly at submission time** (an undeclared gap is worse than a
declared one).

## Item 1 — Solution repository

- [ ] Agent source code
- [ ] System prompts and/or skill descriptions used — saved as files
- [ ] Pipeline config files (e.g. `.github/workflows/*.yml`) running the
      agent as a **separate step**
- [ ] README sufficient for the committee to reproduce independently:
  - [ ] run commands
  - [ ] environment variables
  - [ ] required model-access credentials (how to supply them, not the
        actual keys)
  - [ ] expected output

## Item 2 — Agent's check report on the test project

- [ ] `report.json` per `04-report-schema.md`
- [ ] `report.md`, same content
- [ ] Per violation: requirement ID + text, location, code snippet,
      justification, severity, recommendation
- [ ] Summary: commit, start/end time, duration, overall result,
      violation count, status for **all 8** requirements (incl. clean ones)

## Item 3 — Pipeline step execution log

- [ ] Text log or screenshot
- [ ] Shows exit code, violation count, violated requirement list —
      **without opening the report artifact**

## Item 4 — Approach summary (1–2 pages)

- [ ] Architecture + LLM used
- [ ] Analysis methods
- [ ] Full-analysis-under-context-limit mechanism (§4.4.4): whole
      project vs diff, what happens at the context limit
- [ ] Known limitations (honesty here is scored — completeness metric)

## Item 5 — Resource figures

- [ ] Check runtime (**≤30 minutes**, §4.7.1)
- [ ] Approx. token usage

## Item 6 — Commit ID

- [ ] Test-project commit checked
- [ ] Same commit referenced in the report summary — **must match**

## Extra attention points (organizer doc §3)

- [ ] Fully unattended run, no input prompts, no modifications to the
      checked repo
- [ ] Result actually drives the pipeline: 0 → continue, 1 → block,
      2 → fail = block
- [ ] Non-IB defects (e.g. from Tech Spec) → separate report section,
      **don't block** the pipeline
- [ ] No passwords/keys/tokens/secrets in the report, even ones found in
      someone else's code

## Final check before sending

- [ ] Run the agent on a clean checkout (no local edits) — what's
      submitted must match what actually ran
- [ ] Commit in pipeline log = commit in report = commit stated in item 6
- [ ] `exit_code` ↔ `overall_result` consistent (see table in
      `04-report-schema.md`)
- [ ] Read `report.md` as a first-time reader — is the problem location
      clear without reading the agent's own code?
