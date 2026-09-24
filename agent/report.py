"""Формирование отчёта агента (модуль 4): report.json + report.md по ТЗ п. 4.6.

Структура JSON (см. .claude/04-report-schema.md, расширена):
  meta      — коммит, время начала/окончания, длительность, версия агента, модель, режим
  summary   — overall_result, exit_code, violations_count, requirements_status (все 8),
              requirements (подробно: id по ТЗ, название, текст, статус, число нарушений, что проверено)
  violations           — нарушения Требований ИБ (блокируют пайплайн)
  additional_findings  — несоответствия техспецификации и иные дефекты (не блокируют, ТЗ 4.8.1)
  limitations          — явные ограничения проверки (что не удалось установить)
  resources            — вызовы модели, токены, время
Секреты (пароли, ключи, токены) в отчёт не попадают: все текстовые поля проходят redact().
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import requirements_ru

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_RU = {"critical": "критический", "high": "высокий", "medium": "средний", "low": "низкий"}
STATUS_RU = {
    "pass": "соответствует", "violation": "нарушение", "insufficient_data": "недостаточно данных",
    "not_checked": "не проверено (дедлайн)",
}
STATUS_ICON = {"pass": "✅", "violation": "❌", "insufficient_data": "⚠️", "not_checked": "⏱️"}

# ---------------------------------------------------------------------------
# Редактирование секретов
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|secret_key|api[_-]?key|token|access[_-]?key|private[_-]?key)(\s*[:=]\s*)(['\"]?)([^'\"\s,;)]{4,})"), r"\1\2\3***"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-_.=:+/]{8,}"), "Bearer ***"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), "sk-***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY----- *** -----END PRIVATE KEY-----"),
    (re.compile(r"\b[A-Za-z]+-20\d\d![\w.!@#$%^&*-]{2,}"), "***"),        # учебные пароли вида Training-2026!login
    (re.compile(r"\b[a-f0-9]{40,}\b"), "***hex***"),                        # длинные hex-строки (ключи/хеши)
]


def redact(text):
    if not isinstance(text, str):
        return text
    out = text
    for rx, repl in _SECRET_PATTERNS:
        out = rx.sub(repl, out)
    return out


def redact_deep(obj):
    if isinstance(obj, dict):
        return {k: redact_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_deep(v) for v in obj]
    return redact(obj)


# ---------------------------------------------------------------------------
# Сборка структуры отчёта
# ---------------------------------------------------------------------------

def _finding_id(rid: str, loc: dict, rule_id: str | None) -> str:
    key = f"{rid}|{loc.get('file')}|{loc.get('line')}|{rule_id or 'llm'}"
    return f"{requirements_ru.display_id(rid)}-{hashlib.sha1(key.encode()).hexdigest()[:8]}"


def build_report(*, run_result, commit: str, branch: str | None, started_at: datetime, finished_at: datetime,
                 agent_version: str, model_label: str, analysis_mode: str, project_root: Path, index: dict,
                 usage: dict | None, deadline_seconds: int, timed_out: bool, exit_code: int, extra_limitations: list[str] | None = None) -> dict:
    results = run_result.requirement_results
    violations: list[dict] = []
    req_rows: list[dict] = []
    status_map: dict[str, str] = {}
    for rid in requirements_ru.ORDER:
        res = results.get(rid)
        if res is None:
            status_map[rid] = "not_checked"
            req_rows.append({"id": rid, "display_id": requirements_ru.display_id(rid), "title": requirements_ru.title(rid),
                             "text": requirements_ru.text(rid), "status": "not_checked", "violations_count": 0,
                             "summary": "проверка не выполнена", "checked": [], "checked_files": [], "analysis_mode": "-"})
            continue
        status_map[rid] = res.status
        for v in sorted(res.violations, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.location.get("file") or "", x.location.get("line") or 0)):
            loc = dict(v.location)
            violations.append({
                "id": _finding_id(rid, loc, v.rule_id),
                "requirement_id": rid,
                "requirement_display_id": requirements_ru.display_id(rid),
                "requirement_title": requirements_ru.title(rid),
                "requirement_text": requirements_ru.text(rid),
                "location": {"file": loc.get("file"), "line": loc.get("line"), "function": loc.get("function")},
                "related_locations": list(v.related_locations or []),
                "evidence": v.evidence_snippet,
                "justification": v.justification,
                "severity": v.severity,
                "severity_ru": SEVERITY_RU.get(v.severity, v.severity),
                "confidence": v.confidence,
                "recommendation": v.recommendation,
                "source": v.source,
                "spec_refs": list(v.spec_refs or []),
                "model_comment": v.llm_comment,
            })
        req_rows.append({
            "id": rid, "display_id": requirements_ru.display_id(rid), "title": requirements_ru.title(rid),
            "text": requirements_ru.text(rid), "status": res.status, "status_ru": STATUS_RU.get(res.status, res.status),
            "violations_count": len(res.violations), "summary": res.summary,
            "insufficient_data_reason": res.insufficient_data_reason,
            "analysis_warning": getattr(res, "analysis_warning", None),
            "checked": list(run_result.checked.get(rid, [])), "checked_files": list(res.checked_files or []),
            "analysis_mode": res.analysis_mode, "llm_rounds": res.llm_rounds,
            "rejected_model_candidates": len(res.rejected),
        })
    severity_counts = {s: sum(1 for v in violations if v["severity"] == s) for s in SEVERITY_ORDER}
    failed = [requirements_ru.display_id(rid) for rid, st in status_map.items() if st == "violation"]
    overall = "fail" if violations else "pass"
    limitations = list(run_result.limitations) + list(extra_limitations or [])
    for rid, res in results.items():
        analysis_warning = getattr(res, "analysis_warning", None)
        if analysis_warning:
            # сбой/нераспознанный ответ модели при статусе по правилам — фиксируется всегда
            limitations.append(f"{requirements_ru.display_id(rid)}: {analysis_warning}")
        elif res.status == "insufficient_data" and res.insufficient_data_reason:
            limitations.append(f"{requirements_ru.display_id(rid)}: {res.insufficient_data_reason}")
        if res.rejected:
            limitations.append(f"{requirements_ru.display_id(rid)}: отклонено {len(res.rejected)} кандидатов модели без подтверждённого местоположения — в отчёт не включены.")
    if run_result.timed_out_requirements:
        limitations.append("Дедлайн проверки: анализ моделью не выполнен для " + ", ".join(requirements_ru.display_id(r) for r in run_result.timed_out_requirements) + " (учтены только детерминированные правила).")
    inv = index.get("inventory", {}) or {}
    additional = []
    for a in run_result.additional_findings:
        a = dict(a)
        a.setdefault("source", "rule")
        additional.append(a)
    report = {
        "meta": {
            "commit": commit,
            "branch": branch,
            "started_at": started_at.isoformat(timespec="seconds"),
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "duration_seconds": int((finished_at - started_at).total_seconds()),
            "deadline_seconds": deadline_seconds,
            "timed_out": timed_out,
            "agent": "otcysquad IB-check agent",
            "agent_version": agent_version,
            "model": model_label,
            "analysis_mode": analysis_mode,
            "project_root": str(project_root),
            "project_files_total": inv.get("total_files"),
            "project_files_by_category": inv.get("by_category"),
        },
        "summary": {
            "overall_result": overall,
            "exit_code": exit_code,
            "violations_count": len(violations),
            "violations_by_severity": severity_counts,
            "requirements_failed": failed,
            "requirements_status": status_map,
            "requirements": req_rows,
            "additional_findings_count": len(additional),
        },
        "violations": violations,
        "additional_findings": additional,
        "limitations": limitations,
        "resources": {"llm": usage or {}, "llm_calls": run_result.llm_calls},
    }
    # секреты вычищаются из всего, кроме служебных метаданных (коммит — 40-символьный hex)
    meta = report["meta"]
    report = redact_deep(report)
    report["meta"] = meta
    return report


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _md_escape(s) -> str:
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def _fence(lang: str, body: str) -> str:
    fence = "```"
    while fence in body:
        fence += "`"
    return f"{fence}{lang}\n{body}\n{fence}"


def render_markdown(report: dict) -> str:
    m, s = report["meta"], report["summary"]
    icon = "❌ FAIL" if s["overall_result"] == "fail" else "✅ PASS"
    lines: list[str] = []
    lines.append("# Отчёт агента проверки требований ИБ")
    lines.append("")
    lines.append(f"**Коммит:** `{m['commit']}`" + (f" (ветка `{m['branch']}`)" if m.get("branch") else ""))
    lines.append(f"**Начало:** {m['started_at']} · **Окончание:** {m['finished_at']} · **Длительность:** {m['duration_seconds']} с"
                 + (" · ⏱️ дедлайн превышен, отчёт частичный" if m.get("timed_out") else ""))
    lines.append(f"**Агент:** {m['agent']} v{m['agent_version']} · **Модель:** {m['model']} · **Режим:** {m['analysis_mode']}")
    lines.append(f"**Проект:** файлов в инвентаре — {m.get('project_files_total')} (анализируется проект целиком, а не только изменённые в коммите файлы)")
    lines.append("")
    lines.append(f"## Результат: {icon} (код завершения {s['exit_code']}) — нарушений Требований ИБ: **{s['violations_count']}**")
    if s["requirements_failed"]:
        lines.append(f"Нарушены требования: **{', '.join(s['requirements_failed'])}**")
    sev = s["violations_by_severity"]
    lines.append(f"По критичности: критический {sev.get('critical',0)} · высокий {sev.get('high',0)} · средний {sev.get('medium',0)} · низкий {sev.get('low',0)}")
    lines.append("")
    lines.append("## Статус по каждому требованию")
    lines.append("")
    lines.append("| Требование | Название | Статус | Нарушений | Способ проверки |")
    lines.append("|---|---|---|---|---|")
    for r in s["requirements"]:
        st = f"{STATUS_ICON.get(r['status'],'')} {STATUS_RU.get(r['status'], r['status'])}"
        lines.append(f"| {r['display_id']} | {_md_escape(r['title'])} | {st} | {r['violations_count']} | {_md_escape(r.get('analysis_mode'))} |")
    lines.append("")
    lines.append("### Что именно проверено")
    lines.append("")
    for r in s["requirements"]:
        lines.append(f"- **{r['display_id']}** — {_md_escape(r.get('summary') or '')}")
        for c in r.get("checked", []):
            lines.append(f"  - {_md_escape(c)}")
        if r.get("checked_files"):
            who = "моделью" if str(r.get("analysis_mode", "")).startswith("llm") else "агентом"
            lines.append(f"  - файлы, проанализированные {who}: {', '.join('`'+f+'`' for f in r['checked_files'][:25])}")
        if r.get("insufficient_data_reason"):
            lines.append(f"  - ⚠️ {_md_escape(r['insufficient_data_reason'])}")
        if r.get("analysis_warning"):
            lines.append(f"  - ⚠️ анализ моделью: {_md_escape(r['analysis_warning'])}")
    lines.append("")
    lines.append("## Нарушения Требований ИБ")
    lines.append("")
    if not report["violations"]:
        lines.append("Нарушений не выявлено.")
    by_req: dict[str, list[dict]] = {}
    for v in report["violations"]:
        by_req.setdefault(v["requirement_id"], []).append(v)
    for rid in requirements_ru.ORDER:
        vs = by_req.get(rid)
        if not vs:
            continue
        lines.append(f"### {requirements_ru.display_id(rid)}. {requirements_ru.title(rid)}")
        lines.append("")
        lines.append(f"> {requirements_ru.text(rid)}")
        lines.append("")
        for v in vs:
            loc = v["location"]
            where = f"`{loc['file']}`" + (f", строка {loc['line']}" if loc.get("line") else "") + (f", `{loc['function']}`" if loc.get("function") else "")
            conf = "подтверждено" if v["confidence"] == "confirmed" else "вероятно"
            lines.append(f"#### {v['id']} — {SEVERITY_RU.get(v['severity'], v['severity']).upper()} · {conf} · источник: {v['source']}")
            lines.append("")
            lines.append(f"**Где:** {where}")
            if v.get("related_locations"):
                rel = "; ".join(f"`{x.get('file')}`:{x.get('line')}" + (f" ({x.get('function')})" if x.get('function') else "") for x in v["related_locations"][:20])
                lines.append(f"**Также:** {rel}")
            lines.append("")
            lines.append(_fence("python" if str(loc.get("file", "")).endswith(".py") else "", v["evidence"] or "(строка пуста)"))
            lines.append("")
            lines.append(f"**Обоснование:** {v['justification']}")
            if v.get("model_comment"):
                lines.append(f"**Комментарий модели:** {v['model_comment']}")
            lines.append(f"**Рекомендация:** {v['recommendation']}")
            if v.get("spec_refs"):
                lines.append(f"**Основание:** {', '.join(v['spec_refs'])}")
            lines.append("")
    lines.append("## Несоответствия технической спецификации и иные замечания (не блокируют пайплайн)")
    lines.append("")
    if not report["additional_findings"]:
        lines.append("Замечаний нет.")
    for a in report["additional_findings"]:
        loc = a.get("location") or {}
        where = f"`{loc.get('file')}`" + (f":{loc.get('line')}" if loc.get("line") else "")
        sev = f" [{SEVERITY_RU.get(a['severity'], a['severity'])}]" if a.get("severity") else ""
        lines.append(f"- **{a.get('category','other')}**{sev} — {where}: {_md_escape(a.get('description',''))}")
    lines.append("")
    lines.append("## Ограничения проверки")
    lines.append("")
    if not report["limitations"]:
        lines.append("Ограничений не зафиксировано.")
    for l in report["limitations"]:
        lines.append(f"- {_md_escape(l)}")
    lines.append("")
    res = report.get("resources", {}).get("llm") or {}
    lines.append("## Ресурсы")
    lines.append("")
    lines.append(f"- Вызовов модели: {report.get('resources', {}).get('llm_calls', 0)}; токенов: запрос {res.get('prompt_tokens', 0)}, ответ {res.get('completion_tokens', 0)}, всего {res.get('total_tokens', 0)}; повторов: {res.get('retries', 0)}")
    lines.append(f"- Длительность проверки: {m['duration_seconds']} с (лимит {m['deadline_seconds']} с)")
    lines.append("")
    return "\n".join(lines)


def render_step_summary(report: dict) -> str:
    """Короткая сводка для журнала шага / GITHUB_STEP_SUMMARY (ТЗ 4.3.5)."""
    s = report["summary"]
    m = report["meta"]
    lines = [
        f"IB-check: результат {s['overall_result'].upper()}, код завершения {s['exit_code']}, нарушений: {s['violations_count']}",
        f"Нарушены требования: {', '.join(s['requirements_failed']) or 'нет'}",
        "Статус: " + "; ".join(f"{r['display_id']}={r['status']}({r['violations_count']})" for r in s["requirements"]),
        f"Коммит: {m['commit']}; длительность: {m['duration_seconds']} с; модель: {m['model']}",
    ]
    return "\n".join(lines)


def write_reports(report: dict, json_path: Path, md_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
