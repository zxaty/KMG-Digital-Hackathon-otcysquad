"""Module-3 orchestration: run all 8 IB requirements (rules + LLM), plus the
deterministic Tech-Spec findings, and hand module 4 (report.py) exactly
what it needs.

Requirement routing:
  - IB-06 is resolved without the model (analyzer.analyze_ib06_deterministic
    for README/md/txt + rules.check_ib06 for docx).
  - IB-01…05, 07, 08: rules.py findings first (deterministic), then one
    LLM call per requirement via `client` (analyzer.analyze_requirement),
    which confirms/refines/extends them. With client=None (rules-only
    mode) the rule findings alone form the result.
  - deadline (time.monotonic() value): requirements that could not be
    sent to the model before the deadline get status "not_checked" for
    the LLM part but keep their rule findings (ТЗ 4.7.2 — partial report).

additional_findings = tech_spec_findings (deterministic) + rules.additional
+ spec_gaps reported by the model (all non-blocking, ТЗ 4.8.1).
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, FIRST_EXCEPTION, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import analyzer
import tech_spec_findings

DETERMINISTIC_REQUIREMENTS = ("IB-06",)
LLM_REQUIREMENTS = tuple(rid for rid in analyzer.IB_REQUIREMENTS if rid not in DETERMINISTIC_REQUIREMENTS)


@dataclass
class RunResult:
    requirement_results: dict[str, analyzer.AnalysisResult] = field(default_factory=dict)
    additional_findings: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    checked: dict[str, list[str]] = field(default_factory=dict)
    timed_out_requirements: list[str] = field(default_factory=list)
    llm_calls: int = 0


def run_all(
    index: dict,
    client: analyzer.LLMClient | None,
    project_root: Path,
    rule_outcome=None,
    deadline: float | None = None,
    source_budget_chars: int = analyzer.DEFAULT_SOURCE_BUDGET_CHARS,
    on_progress: Callable[[str, str], None] | None = None,
    concurrency: int = 1,
) -> RunResult:
    """Run every one of the 8 IB requirements and assemble the
    non-blocking additional findings, in one call. `client` is never
    invoked for IB-06."""
    project_root = Path(project_root)
    requirement_results: dict[str, analyzer.AnalysisResult] = {}
    result = RunResult()

    by_req: dict[str, list] = {}
    if rule_outcome is not None:
        for f in rule_outcome.findings:
            by_req.setdefault(f.requirement_id, []).append(f)
        result.limitations.extend(rule_outcome.limitations)
        result.checked = dict(rule_outcome.checked)

    def progress(rid: str, msg: str):
        if on_progress:
            on_progress(rid, msg)

    llm_queue: list[str] = []
    for rid in sorted(analyzer.IB_REQUIREMENTS):
        rule_findings = by_req.get(rid, [])
        if rid in DETERMINISTIC_REQUIREMENTS:
            res = analyzer.analyze_ib06_deterministic(index)
            extra = [analyzer.rule_finding_to_violation(project_root, rf) for rf in rule_findings]
            if extra:
                res.violations.extend(extra)
                res.status = "violation"
            requirement_results[rid] = res
            progress(rid, f"{res.status} (детерминированно)")
            continue
        if client is None:
            requirement_results[rid] = analyzer.rules_only_result(
                rid, project_root, rule_findings, checked=result.checked.get(rid), limitations=result.limitations,
            )
            progress(rid, f"{requirement_results[rid].status} (только правила)")
            continue
        llm_queue.append(rid)

    def timed_out_result(rid: str) -> analyzer.AnalysisResult:
        res = analyzer.rules_only_result(rid, project_root, by_req.get(rid, []), checked=result.checked.get(rid),
                                         reason="дедлайн проверки: анализ моделью пропущен")
        res.status = res.status if res.violations else "not_checked"
        res.analysis_mode = "rules-only (timeout)"
        return res

    def worker(rid: str) -> analyzer.AnalysisResult | None:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        progress(rid, "запрос к модели…")
        res = analyzer.analyze_requirement(rid, index, client, project_root, rule_findings=by_req.get(rid, []),
                                           source_budget_chars=source_budget_chars, deadline=deadline)
        progress(rid, f"{res.status}: нарушений {len(res.violations)}, отклонено {len(res.rejected)}, раундов {res.llm_rounds}")
        return res

    if llm_queue:
        workers = max(1, min(int(concurrency or 1), len(llm_queue)))
        pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="llm")
        try:
            futures = {pool.submit(worker, rid): rid for rid in llm_queue}
            done, pending = wait(futures, return_when=FIRST_EXCEPTION)
            for fut in done:
                exc = fut.exception()
                if exc is not None:
                    for p_ in pending:
                        p_.cancel()
                    raise exc          # LLMUnavailableError → код 2 в main.py
            for fut, rid in futures.items():
                res = fut.result()
                if res is None:
                    requirement_results[rid] = timed_out_result(rid)
                    result.timed_out_requirements.append(rid)
                    progress(rid, "not_checked (дедлайн)")
                else:
                    result.llm_calls += res.llm_rounds
                    requirement_results[rid] = res
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
    requirement_results = {rid: requirement_results[rid] for rid in sorted(requirement_results)}
    result.timed_out_requirements.sort()

    additional = list(tech_spec_findings.assemble_tech_spec_findings(index))
    if rule_outcome is not None:
        additional.extend(rule_outcome.additional)
    def near_existing(g: dict) -> bool:
        gl = g.get("location") or {}
        for a in additional:
            al = a.get("location") or {}
            if al.get("file") == gl.get("file") and isinstance(al.get("line"), int) and isinstance(gl.get("line"), int) \
                    and abs(al["line"] - gl["line"]) <= 2:
                return True
        return False

    for rid, res in requirement_results.items():
        for g in res.spec_gaps:
            if not near_existing(g):
                additional.append(g)
        for d in res.disputed:
            additional.append({
                "category": "disputed-by-model",
                "description": (f"Условный риск по {analyzer.requirements_ru.display_id(rid)} (правило {d['rule_id']}), оспорен моделью: "
                                f"{d['justification']} Контрдовод модели: {d.get('comment') or '—'} "
                                f"(см. {d['counter_evidence']['file']}:{d['counter_evidence']['line']})."),
                "location": d["location"], "source": "rule+llm-dispute",
            })

    result.requirement_results = requirement_results
    result.additional_findings = additional
    return result
