"""Точка входа агента проверки ИБ (модули 1 и 5: интеграция с CI/CD и принятие решения).

    python agent/main.py --project-root . --out-json report.json --out-md report.md

Коды завершения (ТЗ 4.3.3):
  0 — нарушений Требований ИБ не выявлено (пайплайн продолжается);
  1 — выявлено ≥1 нарушение (слияние/развёртывание блокируются);
  2 — проверка не выполнена: модель недоступна / лимиты / ошибка разбора проекта
      (ТЗ 4.7.3 — аварийное завершение БЕЗ формирования отчёта).

Дедлайн (ТЗ 4.7.1–4.7.2): по умолчанию 25 минут; требования, не успевшие к
модели, получают статус not_checked, отчёт формируется в объёме выполненного,
код завершения — по найденным нарушениям (либо 1 при --fail-on-incomplete).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone, timedelta
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(AGENT_DIR))

from indexer import Indexer  # noqa: E402
import analyzer  # noqa: E402
import llm_client  # noqa: E402
import report as report_mod  # noqa: E402
import rules  # noqa: E402
import run_analysis  # noqa: E402
import requirements_ru  # noqa: E402

__version__ = "1.0.1"

EXIT_OK, EXIT_VIOLATIONS, EXIT_ERROR = 0, 1, 2
LOCAL_TZ = timezone(timedelta(hours=5), name="Asia/Almaty")


def log(msg: str):
    ts = datetime.now(LOCAL_TZ).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def gh_annotation(kind: str, msg: str):
    """::error:: / ::warning:: / ::notice:: — аннотации в журнале GitHub Actions."""
    print(f"::{kind}::{msg}", flush=True)


def detect_commit(root: Path) -> tuple[str, str | None]:
    sha = os.environ.get("GITHUB_SHA")
    branch = os.environ.get("GITHUB_REF_NAME")
    if sha and os.environ.get("GITHUB_WORKSPACE") and Path(os.environ["GITHUB_WORKSPACE"]).resolve() == root.resolve():
        return sha, branch
    try:
        sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=20).stdout.strip()
        br = subprocess.run(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, timeout=20).stdout.strip()
        if sha:
            return sha, (br or branch)
    except Exception:
        pass
    return os.environ.get("GITHUB_SHA") or "unknown", branch


def load_dotenv(path: Path) -> None:
    """KEY=VALUE из .env; уже заданные переменные окружения не перезаписываются.
    .env проверяемого проекта намеренно не читается: он не должен управлять агентом."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip().strip('"').strip("'")
        if name and name not in os.environ:
            os.environ[name] = value


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Агент автоматизированной проверки Требований ИБ (ИБ-01…ИБ-08)")
    ap.add_argument("--project-root", default=".", help="корень проверяемого проекта")
    ap.add_argument("--out-json", default="report.json")
    ap.add_argument("--out-md", default="report.md")
    ap.add_argument("--index-out", default=None, help="сохранить статический индекс проекта (JSON) — для отладки")
    ap.add_argument("--commit", default=os.environ.get("IB_CHECK_COMMIT"),
                    help="идентификатор коммита для отчёта, если проект не является git-репозиторием (по умолчанию — git rev-parse HEAD)")
    ap.add_argument("--provider", default=None, help="deepseek | qwen | openai | custom | mock | none (по умолчанию LLM_PROVIDER или deepseek)")
    ap.add_argument("--model", default=None, help="имя модели (по умолчанию LLM_MODEL или пресет провайдера)")
    ap.add_argument("--base-url", default=None, help="базовый URL OpenAI-совместимого API")
    ap.add_argument("--deadline-minutes", type=float, default=25.0, help="внутренний лимит времени проверки (ТЗ 4.7.1: шаг ≤ 30 мин)")
    ap.add_argument("--source-budget-chars", type=int, default=analyzer.DEFAULT_SOURCE_BUDGET_CHARS, help="бюджет символов исходников на один вызов модели")
    ap.add_argument("--fail-on-incomplete", action="store_true", help="возвращать код 1, если по дедлайну проверены не все требования")
    ap.add_argument("--fail-on-insufficient", action="store_true", help="возвращать код 1, если по какому-либо требованию недостаточно данных")
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--llm-concurrency", type=int, default=int(os.environ.get("LLM_CONCURRENCY", "3")),
                    help="сколько требований одновременно отправлять модели (по умолчанию 3; 1 — последовательно)")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")   # консоль Windows (cp1251/cp866) не должна ронять агента
        except (AttributeError, ValueError):
            pass
    load_dotenv(Path.cwd() / ".env")
    load_dotenv(AGENT_DIR / ".env")
    args = parse_args(argv)
    root = Path(args.project_root).resolve()
    started_at = datetime.now(LOCAL_TZ)
    t0 = time.monotonic()
    deadline_seconds = int(args.deadline_minutes * 60)
    # запас минуты на формирование отчёта; при лимите < 2 мин (тесты) — без запаса
    deadline = t0 + (deadline_seconds - 60 if deadline_seconds >= 120 else deadline_seconds)
    log(f"Агент проверки ИБ v{__version__}; проект: {root}")
    if not root.is_dir():
        gh_annotation("error", f"каталог проекта не найден: {root}")
        return EXIT_ERROR

    commit, branch = detect_commit(root)
    if args.commit:
        commit = args.commit
    log(f"Коммит: {commit}" + (f" (ветка {branch})" if branch else ""))

    # --- модуль 2: индекс всего проекта ---
    try:
        index = Indexer(root).build()
    except Exception as exc:
        gh_annotation("error", f"ошибка разбора проекта: {exc}")
        traceback.print_exc()
        return EXIT_ERROR
    inv = index.get("inventory", {})
    log(f"Индекс построен: файлов {inv.get('total_files')}, маршрутов {len(index.get('routes', []))}, моделей {len(index.get('models', []))}, замечаний индексатора {len(index.get('notes', []))}")
    if args.index_out:
        Path(args.index_out).write_text(json.dumps(index, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    # --- модуль 3а: детерминированные правила ---
    rule_outcome = rules.run_rules(index, root)
    by_req: dict[str, int] = {}
    for f in rule_outcome.findings:
        by_req[f.requirement_id] = by_req.get(f.requirement_id, 0) + 1
    log("Правила: находок " + str(len(rule_outcome.findings)) + " (" + ", ".join(f"{requirements_ru.display_id(k)}: {v}" for k, v in sorted(by_req.items())) + ")")

    # --- модуль 3: модель ---
    provider = (args.provider or os.environ.get("LLM_PROVIDER") or "deepseek").lower()
    try:
        client = llm_client.make_client(provider, model=args.model, base_url=args.base_url, max_retries=args.max_retries, log=log)
    except llm_client.LLMConfigError as exc:
        gh_annotation("error", f"конфигурация LLM: {exc}")
        return EXIT_ERROR
    if client is None:
        model_label = "не используется (только правила)"
        analysis_mode = "rules-only"
    elif provider == "mock":
        model_label = "mock"
        analysis_mode = "rules+mock"
    else:
        model_label = f"{client.provider}/{client.model}"
        analysis_mode = "rules+llm"
    log(f"Режим анализа: {analysis_mode}; модель: {model_label}; дедлайн {deadline_seconds} с")

    def progress(rid: str, msg: str):
        log(f"  {requirements_ru.display_id(rid)}: {msg}")

    try:
        run_result = run_analysis.run_all(index, client, root, rule_outcome=rule_outcome, deadline=deadline,
                                          source_budget_chars=args.source_budget_chars, on_progress=progress,
                                          concurrency=args.llm_concurrency)
    except llm_client.LLMUnavailableError as exc:
        gh_annotation("error", f"проверка не выполнена — модель недоступна: {exc}")
        log("Код завершения: 2 (отчёт не формируется, ТЗ 4.7.3)")
        return EXIT_ERROR
    except Exception as exc:
        gh_annotation("error", f"внутренняя ошибка агента: {exc}")
        traceback.print_exc()
        return EXIT_ERROR

    # --- модуль 5: решение ---
    violations_total = sum(len(r.violations) for r in run_result.requirement_results.values())
    insufficient = [rid for rid, r in run_result.requirement_results.items() if r.status == "insufficient_data"]
    timed_out = bool(run_result.timed_out_requirements)
    exit_code = EXIT_VIOLATIONS if violations_total else EXIT_OK
    if exit_code == EXIT_OK and timed_out and args.fail_on_incomplete:
        exit_code = EXIT_VIOLATIONS
    if exit_code == EXIT_OK and insufficient and args.fail_on_insufficient:
        exit_code = EXIT_VIOLATIONS

    finished_at = datetime.now(LOCAL_TZ)
    usage = client.usage.as_dict() if client is not None and hasattr(client, "usage") else None
    extra_limits = []
    if client is None:
        extra_limits.append("Режим только правил: модель не использовалась; семантические дефекты, недоступные статическим правилам, могли остаться не выявленными.")
    rep = report_mod.build_report(
        run_result=run_result, commit=commit, branch=branch, started_at=started_at, finished_at=finished_at,
        agent_version=__version__, model_label=model_label, analysis_mode=analysis_mode, project_root=root, index=index,
        usage=usage, deadline_seconds=deadline_seconds, timed_out=timed_out, exit_code=exit_code, extra_limitations=extra_limits,
    )
    json_path, md_path = Path(args.out_json), Path(args.out_md)
    report_mod.write_reports(rep, json_path, md_path)
    log(f"Отчёт записан: {json_path} и {md_path}")

    # --- журнал шага (ТЗ 4.3.5) ---
    summary = report_mod.render_step_summary(rep)
    print(summary, flush=True)
    failed = rep["summary"]["requirements_failed"]
    if exit_code == EXIT_VIOLATIONS:
        gh_annotation("error", f"выявлено нарушений Требований ИБ: {violations_total}; нарушены: {', '.join(failed) or '—'}; пайплайн блокируется")
    else:
        gh_annotation("notice", "нарушений Требований ИБ не выявлено; пайплайн продолжается")
    if insufficient:
        gh_annotation("warning", "недостаточно данных для вывода по: " + ", ".join(requirements_ru.display_id(r) for r in insufficient))
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        try:
            with open(step_summary, "a", encoding="utf-8") as fh:
                fh.write("## Проверка требований ИБ\n\n")
                fh.write("```\n" + summary + "\n```\n\n")
                fh.write("| Требование | Статус | Нарушений |\n|---|---|---|\n")
                for r in rep["summary"]["requirements"]:
                    fh.write(f"| {r['display_id']} {r['title']} | {r['status']} | {r['violations_count']} |\n")
                fh.write("\n")
        except OSError:
            pass
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        try:
            with open(gh_output, "a", encoding="utf-8") as fh:
                fh.write(f"exit_code={exit_code}\nviolations={violations_total}\nresult={rep['summary']['overall_result']}\n")
                fh.write(f"failed_requirements={', '.join(failed)}\n")
        except OSError:
            pass
    log(f"Код завершения: {exit_code}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
