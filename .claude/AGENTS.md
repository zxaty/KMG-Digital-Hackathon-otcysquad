# AGENTS.md — context for the coding agent

Entry point for Claude Code (or any coding agent) building our **IB
security-check agent** for the hackathon. Read `docs/` in this order
before writing code:

1. `docs/01-task-overview.md` — what we build, how it's scored
2. `docs/02-ib-requirements.md` — the 8 mandatory security requirements
3. `docs/03-test-project-map.md` — map of the target repo we scan
4. `docs/04-report-schema.md` — exact report format (JSON + Markdown)
5. `docs/05-agent-architecture.md` — recommended architecture, exit codes, CI/CD
6. `docs/06-submission-checklist.md` — what gets submitted
7. `docs/07-verification-protocol.md` — **mandatory, read before saying "done"**

## Hard rules (never violate)

- We are building a **checker**, not fixing the target project. Never
  modify the test-project repo.
- The agent runs non-interactively. No prompts to the user during a run.
- The agent analyzes the **whole project**, never just the diff.
- Exit codes: `0` no violations, `1` violations found (block pipeline),
  `2` agent itself failed (model unreachable, limit exceeded, parse
  error) — report may be partial/absent per `05-agent-architecture.md`.
- Report must never contain real secrets (passwords, keys, tokens) even
  when found in target code — redact the value, keep the finding.
- Every violation needs: requirement ID, exact location (file + line/
  function/param), code snippet, justification, severity, fix
  recommendation. Vague, unlocated claims don't count as findings.

## Non-negotiable: verification before "done" (see doc 07 for full protocol)

**Never report a task as complete without having actually run it and
inspected the output.** This applies to every step, not just the final
one:

1. Implement the smallest coherent unit of work.
2. **Run it.** Execute the agent, the test, the CI step — whatever
   proves the claim.
3. **Inspect the actual output** (exit code, report content, logs) —
   not just "did it crash", but "does the output match what was
   specified in the docs above".
4. If it doesn't match → fix it yourself and go back to step 2. Do not
   ask the user for permission to keep iterating on an obvious bug.
5. Only report "done" / "this works" after step 3 passed with real
   evidence you can show (command run + actual output, not a
   paraphrase of expected behavior).
6. If you get stuck after several genuine attempts (not just declaring
   defeat after one try), say exactly what you tried, what failed, and
   what you need — that's the only acceptable reason to stop before
   "done".

Never say "this should work" or "this is now fixed" as a final answer.
Say "I ran X, got Y, which matches/doesn't match Z" instead.

## Stack

_(fill in before starting: agent implementation language, LLM provider,
whether target source code may be sent to an external API — organizer
limits per ТЗ §4.9)._
