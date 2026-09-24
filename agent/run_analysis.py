"""Module-3 orchestration: run all 8 IB requirements plus the
deterministic Tech-Spec findings, and hand module 4 exactly what it
needs to build report.json - nothing about report.json's own shape
lives here (that's module 4's job per docs/04-report-schema.md), this
is purely "collect every analysis result in one call."

Requirement routing:
  - IB-06 is fully resolved by index.json alone (regulatory_references) -
    see analyzer.analyze_ib06_deterministic. No LLM call.
  - The other 7 (IB-01, 02, 03, 04, 05, 07, 08) go through
    analyzer.analyze_requirement, which calls the given LLMClient once
    per requirement (8 calls total become 7 real model calls + 1
    deterministic lookup).

additional_findings (Tech-Spec-only, non-IB) come from
tech_spec_findings.assemble_tech_spec_findings - a separate, also
zero-LLM path, per docs/04-report-schema.md's additional_findings field
(these never affect requirements_status or the exit-code decision).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import analyzer
import tech_spec_findings

DETERMINISTIC_REQUIREMENTS = ("IB-06",)
LLM_REQUIREMENTS = tuple(rid for rid in analyzer.IB_REQUIREMENTS if rid not in DETERMINISTIC_REQUIREMENTS)


@dataclass
class RunResult:
    requirement_results: dict[str, analyzer.AnalysisResult] = field(default_factory=dict)
    additional_findings: list[dict] = field(default_factory=list)


def run_all(index: dict, client: analyzer.LLMClient, project_root: Path) -> RunResult:
    """Run every one of the 8 IB requirements (IB-06 deterministically,
    the other 7 via `client`) and assemble the deterministic Tech-Spec
    additional_findings, in one call. `client` is never invoked for
    IB-06 - see test_run_analysis.py's
    test_ib06_bypasses_the_llm_client_entirely for a mechanical proof of
    that, not just an assertion about the returned status.
    """
    requirement_results: dict[str, analyzer.AnalysisResult] = {}

    for rid in sorted(analyzer.IB_REQUIREMENTS):
        if rid in DETERMINISTIC_REQUIREMENTS:
            requirement_results[rid] = analyzer.analyze_ib06_deterministic(index)
        else:
            requirement_results[rid] = analyzer.analyze_requirement(rid, index, client, project_root)

    additional_findings = tech_spec_findings.assemble_tech_spec_findings(index)

    return RunResult(requirement_results=requirement_results, additional_findings=additional_findings)
