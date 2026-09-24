"""Build the machine- and human-readable module-4 reports."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import analyzer


def build_report(run_result, *, commit: str, started_at: str, finished_at: str,
                 duration_seconds: float, model: str, usage: dict) -> tuple[dict, int]:
    violations = []
    statuses = {}
    limitations = []
    for rid in sorted(analyzer.IB_REQUIREMENTS):
        result = run_result.requirement_results[rid]
        statuses[rid] = result.status
        if result.status == "insufficient_data":
            limitations.append(f"{rid}: {result.insufficient_data_reason}")
        for item in result.violations:
            violations.append({
                "requirement_id": rid,
                "requirement_text": result.requirement_text,
                "location": item.location,
                "evidence": item.evidence_snippet,
                "justification": item.justification,
                "severity": item.severity,
                "recommendation": item.recommendation,
            })
    exit_code = 1 if violations else 0
    report = {
        "meta": {
            "commit": commit,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": round(duration_seconds, 3),
            "agent_version": "1.0.0",
            "model": model,
            "usage": usage,
        },
        "summary": {
            "overall_result": "fail" if exit_code else "pass",
            "exit_code": exit_code,
            "violations_count": len(violations),
            "requirements_status": statuses,
        },
        "violations": violations,
        "additional_findings": run_result.additional_findings,
        "limitations": limitations,
    }
    return report, exit_code


def markdown(report: dict) -> str:
    meta, summary = report["meta"], report["summary"]
    lines = [
        "# IB Security Report", "",
        f"**Commit:** {meta['commit']}",
        f"**Started:** {meta['started_at']} | **Finished:** {meta['finished_at']} | "
        f"**Duration:** {meta['duration_seconds']}s",
        f"**Result:** {summary['overall_result'].upper()} (exit {summary['exit_code']}) — "
        f"{summary['violations_count']} violations", "",
        "## Requirement status", "", "| ID | Status |", "|---|---|",
    ]
    lines.extend(f"| {rid} | {status} |" for rid, status in summary["requirements_status"].items())
    lines.extend(["", "## Violations", ""])
    if not report["violations"]:
        lines.append("None.")
    for finding in report["violations"]:
        loc = finding["location"]
        where = f"{loc.get('file')}:{loc.get('line')}"
        if loc.get("function"):
            where += f" ({loc['function']})"
        lines.extend([
            f"### {finding['requirement_id']} [{finding['severity'].upper()}]", "",
            f"**Where:** `{where}`", "", "```", finding["evidence"], "```", "",
            f"**Why:** {finding['justification']}", "", f"**Fix:** {finding['recommendation']}", "",
        ])
    lines.extend(["## Additional findings (outside IB scope)", ""])
    if not report["additional_findings"]:
        lines.append("None.")
    for finding in report["additional_findings"]:
        loc = finding.get("location", {})
        lines.append(f"- **{finding.get('category', 'other')}** — {finding.get('description', '')} "
                     f"(`{loc.get('file', 'unknown')}:{loc.get('line', '?')}`)")
    lines.extend(["", "## Analysis limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    if not report["limitations"]:
        lines.append("None reported.")
    lines.extend(["", "## Model usage", "",
                  f"- Calls: {meta['usage'].get('calls', 0)}",
                  f"- Prompt tokens: {meta['usage'].get('prompt_tokens', 0)}",
                  f"- Completion tokens: {meta['usage'].get('completion_tokens', 0)}",
                  f"- Total tokens: {meta['usage'].get('total_tokens', 0)}", ""])
    return "\n".join(lines)


def write_reports(report: dict, out_json: Path, out_md: Path) -> None:
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_md.write_text(markdown(report), encoding="utf-8")
