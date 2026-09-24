# 05. Agent architecture and CI/CD integration

## Modules (ТЗ §4.2 — minimum required)

```
1. CI/CD integration module
   entry point for the pipeline step, input params, publishes report
   as a build artifact, returns exit code

2. Context-collection module
   walks the whole project (not diff), selects files, chunks context
   within the model's context-length limit

3. Analysis module
   checks each IB requirement; LLM + optional static/pattern analysis
   as a cheaper, deterministic complementary layer

4. Report-generation module
   maps findings to report.json/report.md schema, ties each finding
   to file/line/function

5. Decision module
   maps the violation list to exit code (0/1/2)
```

Recommendation: don't do "read everything, tell me what's wrong" as one
monolithic LLM call — pass rate and stability drop, and §4.1.3 requires
**deterministic output format** (not necessarily deterministic content,
but the reproducibility score rewards stable re-runs). Splitting into
modules also makes each finding traceable to a specific requirement.

## Full-context-under-limit mechanism (must be documented, §4.4.4)

ТЗ explicitly requires **describing** this mechanism in submitted
materials. Combine as needed:

1. **Project indexing** — file list, routes, models/entities, config
   files. Cheap, deterministic, no LLM needed.
2. **Per-requirement file pre-selection** — e.g. for IB-08 (PII export),
   pre-filter files matching export/csv/download/report patterns, feed
   only those + a role/auth context summary to the LLM.
3. **Staged processing** — pass 1: build the entity/route map (cheap);
   pass 2: targeted per-requirement analysis on its subset of files;
   pass 3: aggregate into the final report.
4. **Partial-result aggregation** — for cross-cutting requirements
   (IB-02, IB-07, partly IB-01/IB-04/IB-08), roll up per-file/per-route
   partial conclusions into one requirement-level verdict (e.g. "11/12
   write endpoints protected, 1 not" → violation, not silent averaging).

**Practical tip:** keep a non-LLM (deterministic) index — routes,
models, config files — as the primary source of "completeness", use
the LLM for judging each found candidate. Cheaper on tokens, and easier
to demonstrate completeness to the review committee.

## Error handling and time limit (§4.7)

- Step time limit: **30 minutes** (§4.7.1). The agent must:
  - on timeout, terminate cleanly and produce a report **covering what
    was actually checked** (partial report still required — §4.7.2),
    return exit code per §4.3.3 based on findings so far;
  - on external-service failure (model unreachable, rate limit) —
    terminate with **exit code 2**, **no report** required (§4.7.3 —
    the only explicitly allowed no-report case).
- These are different branches: "30-min timeout" → partial report +
  code from findings so far; "external service error" → code 2, no
  report.

## Exit codes (§4.3.3, submission-materials doc §3.2–3.3)

```
0  no violations found          → pipeline: continue
1  ≥1 violation (IB-01..08 only) → pipeline: BLOCK merge/deploy
2  agent failed to complete      → pipeline: BLOCK (counts as failed check)
```

§4.3.6: never block the pipeline on zero violations, even with
informational warnings — warnings go in `additional_findings`, not
exit 1.

§4.8.1: Technical-Spec violations (outside IB-01…08) go in a separate
report section and never trigger exit 1/block.

## GitHub Actions integration (scored criterion, 15%)

Explicitly judged:
- Auto-run on push in GitHub Actions with our own skills/prompts.
- Checks the **pre-deploy, current** version (§4.3.2: the IB-check step
  sits **before** merge/deploy steps).
- Correct pass/block decision.
- Error handling (exit code 2) also blocks/doesn't silently pass.
- Report saved as a build artifact, available **regardless of result**
  (§4.3.4).
- Step log must show (§4.3.5, submission-materials §1.3): exit code,
  violation count, list of violated requirements — **visible in the
  step log itself**, without opening the report artifact.

### Workflow skeleton (draft, adapt to agent's stack)

```yaml
name: ib-security-check
on: [push]

jobs:
  ib-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full tree — agent needs the whole project

      - name: Run IB agent
        id: agent
        run: |
          python agent/main.py \
            --project-root . \
            --out-json report.json \
            --out-md report.md
        continue-on-error: true   # let later steps run even on exit 1/2

      - name: Publish report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ib-security-report
          path: |
            report.json
            report.md

      - name: Write job summary
        if: always()
        run: |
          echo "## IB Security Check" >> $GITHUB_STEP_SUMMARY
          echo "Commit: ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
          # print violations_count and requirements_status from report.json here

      - name: Fail pipeline on violations or agent error
        if: steps.agent.outcome == 'failure'
        run: exit 1
```

Key points:
- `continue-on-error: true` on the agent step — otherwise the artifact-
  publish and summary steps never run on exit 1/2, but the report must
  be available **regardless of result** (§4.3.4).
- `fetch-depth: 0` — needed if the agent wants history or the full tree,
  not just the latest commit.
- The final step explicitly translates the agent's exit code into the
  job result — that's what actually blocks merge/deploy.

## Don't

- Analyze only `git diff` — direct violation of §4.4.1.
- Modify the test project — §4.1.5 / submission-materials §3.1.
- Prompt for input during a run — §4.1.2 / §3.1.
- Downgrade/filter findings without an explicit stated reason in the
  report — hurts both accuracy and completeness scores.
