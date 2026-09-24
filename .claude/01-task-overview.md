# 01. Task overview

Organizer: KMG Digital LLP. Hackathon: "AI agent for automated
information-security compliance checks during software development,
integrated into CI/CD."

## What we build

An agent that:

1. Runs as a **separate CI/CD pipeline step** on push, no human input.
2. Analyzes the **entire project** (code, config, dependencies, CI/CD
   files, docs) — not just files changed in the triggering commit.
   Reason: some requirements are cross-cutting (IB-07) and can't be
   verified from a single file.
3. Checks compliance against **8 IB requirements** (`02-ib-requirements.md`)
   plus the project's Technical Specification (extra defects go in a
   separate report section, don't block the pipeline).
4. Produces a structured report: `report.json` (machine-readable) +
   `report.md` (human-readable).
5. Returns an **exit code** that drives the pipeline:
   - `0` no violations → pipeline continues
   - `1` ≥1 violation → pipeline blocked (merge/deploy denied)
   - `2` agent itself failed to complete the check (model unreachable,
     rate limit, parse error) → also counts as a failed check

## Scoring (weights)

| Criterion | Weight | What's judged |
|---|---|---|
| Vulnerability detection | 50% | Coverage of the 8 required checks + extra findings, significance, evidence |
| Accuracy | 10% | No false positives/dupes, correct severity, confirmed vs. conditional findings |
| Analysis completeness | 5% | Whole-project analysis incl. component relations; explicit "checked" vs "insufficient data" |
| CI/CD integration | 15% | Auto-run in GitHub Actions, checks the pre-deploy version, correct pass/block, error handling |
| Report quality | 15% | Human-readable + machine-readable, evidence per finding, consistency with pipeline decision, no leaked secrets |
| Reproducibility & efficiency | 5% | Runs from provided instructions, stable across re-runs, within time/resource limits |

**Strategy takeaway:** 50% is detection completeness/evidence quality,
not architectural elegance. Priorities in order: (1) the agent actually
catches all 8 requirements including cross-cutting ones, (2) the report
strictly matches the §4.6 schema, (3) the pipeline blocks/passes
correctly and consistently with the report.

## Test project

Provided by the organizer, unmodified by us. At least 2 versions exist:

- **Reference version** — no IB violations.
- **Version with injected violations** — deliberately broken, including
  cross-cutting requirement violations (not localized to one file).

The answer key (exact injected locations) is not given to participants —
the agent must find violations on its own.

## Constraints to confirm before starting

- Allowed LLM providers/limits — set by organizer (ТЗ §4.9.1).
- Whether target source may be sent to external APIs — pending
  confirmation (ТЗ §4.9.2). Until confirmed, design so it **can** work
  without shipping full source externally (see file-selection mechanism
  in `05-agent-architecture.md`).
- Pipeline internet access — set by organizer (ТЗ §4.9.3).
