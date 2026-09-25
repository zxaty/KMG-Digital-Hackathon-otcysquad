"""Per-requirement LLM analysis (IB-check agent, module 3).

Design:

- One LLM call per IB requirement (plus at most one follow-up round when
  the model asks for extra files), not per finding-candidate. Module 2
  (agent/indexer.py) enumerates candidates deterministically; module 3a
  (agent/rules.py) turns the unambiguous ones into confirmed findings.
  The model receives BOTH: the structured evidence AND the real source
  of the files relevant to the requirement (numbered lines, within a
  character budget), plus the rule findings as established facts. Its
  job: confirm/refine, find what rules cannot see, and never contradict
  a fact without citing counter-evidence.

- The model never states `requirement_id`, `requirement_text` or the
  code `evidence` snippet. Those come from requirements_ru.py and from
  re-reading the real file at the reported (file, line).

- "No real file+line -> doesn't count" (ТЗ 4.6.4) is enforced here:
  every model-reported location must be inside the evidence sent to it
  (structured rows or an included source file). Anything else is
  rejected and logged, never silently kept or promoted to "pass".

- Whole-project completeness under a context limit (ТЗ 4.4.4): the
  project inventory (every file) is always in the prompt; per-requirement
  file pre-selection picks the relevant sources; the model may request
  additional files by path (`need_files`) for one more round; results
  are aggregated per requirement, then across requirements by module 4.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import requirements_ru

ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")
DEFAULT_SEVERITY = "medium"
DEFAULT_SOURCE_BUDGET_CHARS = 240_000   # ≈ 60–80k токенов; DeepSeek/Qwen держат больше, но так быстрее и дешевле
MAX_FILE_CHARS = 120_000               # один файл больше этого — усекается с пометкой
EXTRA_ROUND_BUDGET_CHARS = 160_000


# ---------------------------------------------------------------------------
# Requirement table - text stamped onto every finding, never model-generated
# ---------------------------------------------------------------------------

IB_REQUIREMENTS: dict[str, str] = {rid: requirements_ru.text(rid) for rid in requirements_ru.ORDER}


# ---------------------------------------------------------------------------
# LLM client abstraction - swappable, so the validation pipeline is testable
# without any network access or credentials.
# ---------------------------------------------------------------------------

class LLMClient(Protocol):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """Return the raw text response for a single-turn completion."""
        ...


@dataclass
class MockLLMClient:
    """Returns a pre-scripted response. Used in tests to prove the
    evidence-bundling and validation pipeline works without a real API."""
    scripted_response: str

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return self.scripted_response



# ---------------------------------------------------------------------------
# Evidence-bundle builders - one per requirement (structured part).
# ---------------------------------------------------------------------------

def _slim_route(r: dict, keys: tuple[str, ...]) -> dict:
    return {k: r.get(k) for k in keys}


_ROUTE_KEYS_FOR_GUARD_ANALYSIS = (
    "pattern", "name", "view_module", "view_function", "view_file", "view_line",
    "url_level_wrappers", "decorators", "body_guard_calls", "audit_calls",
)


def build_evidence_ib01(index: dict) -> dict:
    routes = [_slim_route(r, _ROUTE_KEYS_FOR_GUARD_ANALYSIS) for r in index.get("routes", [])]
    return {
        "routes": routes,
        "guard_definitions": index.get("guard_definitions", {}),
        "installed_apps": index.get("settings", {}).get("INSTALLED_APPS", {}).get("value"),
    }


def build_evidence_ib02(index: dict) -> dict:
    routes = [_slim_route(r, _ROUTE_KEYS_FOR_GUARD_ANALYSIS) for r in index.get("routes", [])]
    return {
        "routes": routes,
        "token_lifecycle": index.get("token_lifecycle", {}),
        "middleware": index.get("settings", {}).get("MIDDLEWARE", {}).get("value"),
        "session_settings": {k: index.get("settings", {}).get(k) for k in ("SESSION_COOKIE_AGE", "SESSION_COOKIE_HTTPONLY", "SESSION_COOKIE_SAMESITE", "SESSION_EXPIRE_AT_BROWSER_CLOSE") if k in index.get("settings", {})},
    }


def build_evidence_ib03(index: dict) -> dict:
    keys = (
        "SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SECURE_SSL_REDIRECT",
        "SECURE_HSTS_SECONDS", "SECURE_HSTS_INCLUDE_SUBDOMAINS", "SECURE_PROXY_SSL_HEADER", "SECURE_CONTENT_TYPE_NOSNIFF",
        "ALLOWED_HOSTS", "DEBUG",
    )
    settings = index.get("settings", {})
    return {
        "relevant_settings": {k: settings[k] for k in keys if k in settings},
        "auxiliary_configs": index.get("auxiliary_configs", {}),
    }


def build_evidence_ib04(index: dict) -> dict:
    pii_models = []
    for m in index.get("models", []):
        pii_fields = [f for f in m.get("fields", []) if f.get("pii_name_hint")]
        if pii_fields:
            pii_models.append({
                "app_dir": m["app_dir"], "file": m["file"], "class_name": m["class_name"],
                "line": m["line"], "pii_fields": pii_fields,
            })
    settings = index.get("settings", {})
    return {
        "password_hashers": settings.get("PASSWORD_HASHERS", {}),
        "auth_user_model": settings.get("AUTH_USER_MODEL", {}),
        "databases": settings.get("DATABASES", {}),
        "storages": settings.get("STORAGES", {}),
        "pii_flagged_model_fields": pii_models,
        "password_bypass_writes": index.get("password_bypass_writes", []),
    }


def build_evidence_ib05(index: dict) -> dict:
    return {
        "log_protection": index.get("log_protection", {}),
        "logging_setting": index.get("settings", {}).get("LOGGING", {}),
        "log_key_setting": index.get("settings", {}).get("LOG_KEY_FILE", {}),
    }


def build_evidence_ib06(index: dict) -> dict:
    return {"regulatory_references": index.get("regulatory_references", {})}


def build_evidence_ib08(index: dict) -> dict:
    hints = ("export", "download", "print", "csv", "xlsx", "dump", "people", "directory")
    keys = ("pattern", "view_function", "view_file", "view_line", "url_level_wrappers", "decorators", "body_guard_calls", "audit_calls")
    routes = []
    for r in index.get("routes", []):
        name_blob = f"{r.get('view_function','')} {r.get('pattern','')}".lower()
        if any(h in name_blob for h in hints):
            routes.append(_slim_route(r, keys))
    return {
        "export_like_routes": routes,
        "guard_definitions": index.get("guard_definitions", {}),
    }


def build_evidence_ib07(index: dict) -> dict:
    bulk_candidates = [h for h in index.get("bulk_orm_calls", []) if h.get("looks_like_queryset")]
    coverage = index.get("model_audit_coverage", [])
    uncovered = [m for m in coverage if not m.get("covered_by_post_save_post_delete_signals")]
    routes = [_slim_route(r, ("pattern", "view_function", "view_file", "view_line", "audit_calls")) for r in index.get("routes", [])]
    return {
        "signal_connections": index.get("signal_wiring", {}).get("connections", []),
        "handler_app_label_filters": index.get("signal_wiring", {}).get("handler_app_label_filters", {}),
        "model_count_total": len(coverage),
        "model_count_uncovered": len(uncovered),
        "uncovered_models": uncovered,
        "bulk_orm_bypass_candidates": bulk_candidates,
        "routes_with_audit_calls": routes,
        "middleware": index.get("settings", {}).get("MIDDLEWARE", {}).get("value"),
        "databases": index.get("settings", {}).get("DATABASES", {}),
        "logging_setting": index.get("settings", {}).get("LOGGING", {}),
    }


EVIDENCE_BUILDERS = {
    "IB-01": build_evidence_ib01,
    "IB-02": build_evidence_ib02,
    "IB-03": build_evidence_ib03,
    "IB-04": build_evidence_ib04,
    "IB-05": build_evidence_ib05,
    "IB-06": build_evidence_ib06,
    "IB-07": build_evidence_ib07,
    "IB-08": build_evidence_ib08,
}


# ---------------------------------------------------------------------------
# Source selection per requirement (context builder, ТЗ 4.4.4)
# ---------------------------------------------------------------------------

SOURCE_PATTERNS: dict[str, list[str]] = {
    # порядок = приоритет включения в контекст
    "IB-01": [r"urls\.py$", r"(^|/)(access|permissions?|decorators?|guards?)\.py$", r"(^|/)views(/|\.py$)", r"middleware", r"settings\.py$", r"templates/.*(manage|admin|base|nav).*\.html$"],
    "IB-02": [r"urls\.py$", r"(^|/)views(/|\.py$)", r"(^|/)(api|auth\w*|tokens?|access|permissions?)\.py$", r"middleware", r"settings\.py$"],
    "IB-03": [r"settings\.py$", r"^[^/]*\.json$", r"(^|/)(serve|server|proxy|gateway|wsgi|asgi|run\w*)\.py$", r"(nginx|apache|caddy|traefik).*\.conf$", r"docker-compose.*\.ya?ml$", r"Dockerfile", r"\.github/workflows/.*\.ya?ml$"],
    "IB-04": [r"(^|/)models\.py$", r"(^|/)hashers?\.py$", r"settings\.py$", r"(^|/)storage\w*\.py$", r"(^|/)(seed|fixtures?|initial)\w*\.py$", r"management/commands/.*\.py$", r"(^|/)setup\w*\.py$"],
    "IB-05": [r"(^|/)(audit|journal|logs?|logging|events?)\w*\.py$", r"(^|/)(local_acl|acl|permissions_fs|filesystem)\w*\.py$", r"(^|/)collector\w*\.py$", r"(^|/)setup\w*\.py$", r"settings\.py$", r"(^|/)serve\.py$"],
    "IB-06": [r"^README\.md$", r"^docs/.*\.(md|txt)$"],
    "IB-07": [r"(^|/)(audit|journal|logs?|events?)\w*\.py$", r"(^|/)apps\.py$", r"middleware", r"(^|/)views(/|\.py$)", r"urls\.py$", r"settings\.py$", r"(^|/)collector\w*\.py$", r"(^|/)signals\.py$", r"management/commands/(db_access|.*audit.*)\.py$"],
    "IB-08": [r"(^|/)views(/|\.py$)", r"urls\.py$", r"(^|/)(access|permissions?)\.py$", r"(^|/)(audit|journal)\w*\.py$", r"(^|/)(export|report)\w*\.py$"],
}
# файлы библиотечного форка (src/helpdesk) подключаются только по явному запросу модели,
# кроме тех, на которые ссылаются маршруты проекта
LIBRARY_DIR_RE = re.compile(r"^src/")


def _numbered(text: str, max_chars: int) -> tuple[str, int, bool]:
    lines = text.splitlines()
    out_lines = []
    used = 0
    truncated = False
    for i, line in enumerate(lines, start=1):
        s = f"{i:5d}| {line}"
        if used + len(s) + 1 > max_chars:
            truncated = True
            break
        out_lines.append(s)
        used += len(s) + 1
    if truncated:
        out_lines.append(f"      | … файл усечён: показано {len(out_lines)} из {len(lines)} строк …")
    return "\n".join(out_lines), len(lines), truncated


def project_map(index: dict) -> dict:
    inv = index.get("inventory", {}) or {}
    files = inv.get("files", [])
    keep = [f for f in files if f["category"] in ("code", "config", "dependencies", "ci", "docs", "shell")]
    return {
        "total_files": inv.get("total_files"),
        "by_category": inv.get("by_category"),
        "files": [f"{f['path']} ({f['size']} B)" for f in keep],
        "note": "Полный перечень файлов кода/конфигурации/документации проекта. Шаблоны, статика и локали перечислены только в by_category; любой файл можно запросить через need_files.",
    }


def select_source_files(requirement_id: str, index: dict, extra: list[str] | None = None) -> list[str]:
    inv = index.get("inventory", {}) or {}
    all_paths = [f["path"] for f in inv.get("files", [])]
    chosen: list[str] = []
    route_files = {r.get("view_file") for r in index.get("routes", []) if r.get("view_file")}
    guard_files = {d.get("file") for d in (index.get("guard_definitions") or {}).values() if d.get("file")}
    meta = index.get("meta", {})
    always = [p for p in (meta.get("settings_file"), meta.get("urlconf_file")) if p]
    for p in always:
        if p not in chosen:
            chosen.append(p)
    for rx in SOURCE_PATTERNS.get(requirement_id, []):
        crx = re.compile(rx)
        for path in sorted(all_paths):
            if LIBRARY_DIR_RE.match(path) and path not in route_files and path not in guard_files:
                continue
            if crx.search(path) and path not in chosen:
                chosen.append(path)
    for p in sorted(route_files | guard_files):
        if requirement_id in ("IB-01", "IB-02", "IB-07", "IB-08") and p not in chosen:
            chosen.append(p)
    for p in extra or []:
        if p in all_paths and p not in chosen:
            chosen.append(p)
    return chosen


def attach_sources(evidence: dict, index: dict, project_root: Path, requirement_id: str,
                   budget_chars: int = DEFAULT_SOURCE_BUDGET_CHARS, extra: list[str] | None = None) -> dict:
    """Добавляет в evidence реальные исходники (нумерованные строки) в пределах бюджета."""
    files = select_source_files(requirement_id, index, extra)
    sources: dict[str, dict] = dict(evidence.get("source_files") or {})
    used = sum(len(v["content"]) for v in sources.values())
    skipped: list[str] = []
    for rel in files:
        if rel in sources:
            continue
        path = project_root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            skipped.append(rel)
            continue
        remaining = budget_chars - used
        if remaining <= 2000:
            skipped.append(rel)
            continue
        content, total_lines, truncated = _numbered(text, min(MAX_FILE_CHARS, remaining))
        sources[rel] = {"lines": total_lines, "truncated": truncated, "content": content}
        used += len(content)
    evidence["source_files"] = sources
    evidence["source_files_skipped_by_budget"] = skipped
    evidence["project_map"] = project_map(index)
    return evidence


def collect_known_locations(evidence: dict) -> set[tuple[str, int]]:
    """Every (file, line) pair present anywhere in the evidence bundle -
    the allowlist a model-reported violation location must belong to.
    Included source files contribute every line 1..N (or 1..shown)."""
    found: set[tuple[str, int]] = set()

    def walk(obj):
        if isinstance(obj, dict):
            if "file" in obj and "line" in obj and isinstance(obj.get("line"), int):
                found.add((obj["file"], obj["line"]))
            if "view_file" in obj and isinstance(obj.get("view_line"), int):
                found.add((obj["view_file"], obj["view_line"]))
            for k, v in obj.items():
                if k == "source_files" and isinstance(v, dict):
                    for rel, info in v.items():
                        shown = info.get("content", "").count("\n") + 1
                        n = min(info.get("lines", 0), shown) if info.get("truncated") else info.get("lines", 0)
                        for i in range(1, (n or 0) + 1):
                            found.add((rel, i))
                else:
                    walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(evidence)
    return found


# ---------------------------------------------------------------------------
# Prompting (русский язык — язык ТЗ и экспертной комиссии)
# ---------------------------------------------------------------------------

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
SKILLS_DIR = Path(__file__).resolve().parent / "skills"

# Системная подсказка и навыки проверки хранятся отдельными файлами
# (состав сдаваемых материалов, п. 1.1) — единственный источник истины.
SYSTEM_PROMPT = (PROMPTS_DIR / "system.md").read_text(encoding="utf-8").strip()


def load_skill(requirement_id: str) -> str:
    path = SKILLS_DIR / f"{requirement_id}.md"
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def build_user_prompt(requirement_id: str, requirement_text: str, evidence: dict,
                      rule_findings: list[dict] | None = None, round_no: int = 1, note: str | None = None) -> str:
    req = requirements_ru.REQUIREMENTS.get(requirement_id, {})
    header = (
        f"Requirement {requirement_id}: {req.get('title', '')}\n"
        f"Идентификатор по ТЗ: {req.get('display_id', requirement_id)}. Связанные пункты: {', '.join(req.get('spec_refs', []))}.\n"
        f"Текст требования: {requirement_text}\n\n"
    )
    parts = [header]
    skill = load_skill(requirement_id)
    if skill:
        parts.append("=== Навык проверки (методика для этого требования) ===\n" + skill + "\n\n")
    if note:
        parts.append(f"Примечание к раунду {round_no}: {note}\n\n")
    parts.append("=== rule_findings (установленные факты; подтверди или оспорь в rule_findings_review) ===\n")
    parts.append(json.dumps(rule_findings or [], indent=1, ensure_ascii=False) + "\n\n")
    structured = {k: v for k, v in evidence.items() if k not in ("source_files", "project_map", "source_files_skipped_by_budget")}
    parts.append("=== Структурированные данные статического индекса (file/line отсюда допустимы для ссылок) ===\n")
    parts.append(json.dumps(structured, indent=1, ensure_ascii=False, default=str) + "\n\n")
    pm = evidence.get("project_map")
    if pm:
        parts.append("=== project_map: все файлы кода/конфигурации/документации проекта ===\n")
        parts.append(json.dumps(pm, indent=1, ensure_ascii=False) + "\n\n")
    skipped = evidence.get("source_files_skipped_by_budget") or []
    if skipped:
        parts.append(f"Файлы, не включённые из-за бюджета контекста (можно запросить через need_files): {skipped}\n\n")
    sources = evidence.get("source_files") or {}
    if sources:
        parts.append("=== Исходники релевантных файлов (номер строки | текст) ===\n")
        for rel, info in sources.items():
            parts.append(f"\n----- {rel} ({info.get('lines')} строк{', усечён' if info.get('truncated') else ''}) -----\n")
            parts.append(info.get("content", "") + "\n")
    parts.append("\nВерни JSON-объект по схеме из системной подсказки.")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Response parsing & validation
# ---------------------------------------------------------------------------

@dataclass
class Violation:
    location: dict
    justification: str
    severity: str
    recommendation: str
    evidence_snippet: str
    source: str = "llm"                     # llm | rule:<rule_id> | rule+llm
    confidence: str = "likely"              # confirmed | likely
    rule_id: str | None = None
    related_locations: list = field(default_factory=list)
    spec_refs: list = field(default_factory=list)
    llm_comment: str | None = None


@dataclass
class RejectedCandidate:
    raw: dict
    reason: str


@dataclass
class AnalysisResult:
    requirement_id: str
    requirement_text: str
    status: str  # "pass" | "violation" | "insufficient_data" | "not_checked"
    summary: str
    violations: list[Violation] = field(default_factory=list)
    rejected: list[RejectedCandidate] = field(default_factory=list)
    insufficient_data_reason: str | None = None
    raw_model_output: str = ""
    parse_error: str | None = None
    spec_gaps: list[dict] = field(default_factory=list)
    disputed: list[dict] = field(default_factory=list)      # rule findings оспоренные моделью (с counter_evidence)
    checked_files: list[str] = field(default_factory=list)
    llm_rounds: int = 0
    analysis_mode: str = "llm"                              # llm | rules-only | deterministic
    json_retry_used: bool = False                           # был ли повтор запроса из-за непригодного ответа
    model_failure: str | None = None                        # модель так и не дала пригодного ответа
    # проблема анализа моделью при статусе, установленном по подтверждённым находкам правил
    # (вместо противоречивой пары status="violation" + insufficient_data_reason); → «Ограничения»
    analysis_warning: str | None = None


def extract_snippet(project_root: Path, file: str, line: int, context: int = 0) -> str | None:
    path = project_root / file
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    if not (1 <= line <= len(lines)):
        return None
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    return "\n".join(lines[start:end])


SNIPPET_MAX_LINES = 18


def smart_snippet(project_root: Path, file: str, line: int) -> str | None:
    """Фрагмент-доказательство: если строка — начало функции/класса (или её
    декоратор), возвращается определение целиком с декораторами (до
    SNIPPET_MAX_LINES строк); иначе — сама строка (байт-в-байт)."""
    single = extract_snippet(project_root, file, line)
    if single is None or not str(file).endswith(".py"):
        return single
    import ast as _ast
    try:
        src = (project_root / file).read_text(encoding="utf-8", errors="replace")
        tree = _ast.parse(src)
    except Exception:
        return single
    lines = src.splitlines()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            first = min([d.lineno for d in node.decorator_list] + [node.lineno])
            if first <= line <= node.lineno:
                end = getattr(node, "end_lineno", node.lineno) or node.lineno
                last = min(end, first + SNIPPET_MAX_LINES - 1)
                chunk = lines[first - 1:last]
                if last < end:
                    chunk.append("    …")
                return "\n".join(chunk)
    return single


def extract_json_object(raw: str) -> dict:
    """Достаёт первый JSON-объект из ответа модели (в т.ч. в ```json … ```)."""
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start < 0:
        raise json.JSONDecodeError("no JSON object in model output", raw, 0)
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise json.JSONDecodeError("unbalanced JSON object in model output", raw, start)


def rule_finding_to_violation(project_root: Path, rf) -> Violation:
    d = rf.to_dict() if hasattr(rf, "to_dict") else dict(rf)
    snippet = smart_snippet(project_root, d["file"], d.get("line") or 1) or ""
    return Violation(
        location={"file": d["file"], "line": d.get("line"), "function": d.get("function")},
        justification=d["justification"], severity=d["severity"], recommendation=d["recommendation"],
        evidence_snippet=snippet, source=f"rule:{d['rule_id']}", confidence=d.get("confidence", "confirmed"),
        rule_id=d["rule_id"], related_locations=d.get("related_locations") or [], spec_refs=d.get("spec_refs") or [],
    )


def _same_place(a: dict, b: dict, tolerance: int = 3) -> bool:
    if a.get("file") != b.get("file"):
        return False
    la, lb = a.get("line"), b.get("line")
    if isinstance(la, int) and isinstance(lb, int) and abs(la - lb) <= tolerance:
        return True
    fa, fb = a.get("function"), b.get("function")
    return bool(fa and fb and fa == fb)


def analyze_ib06_deterministic(index: dict) -> AnalysisResult:
    """IB-06 без вызова модели: regulatory_references индекса уже содержит
    построчные доказательства по каждому акту (README/md/txt); docx — в
    rules.check_ib06 (сливается оркестратором)."""
    requirement_text = IB_REQUIREMENTS["IB-06"]
    rr = index.get("regulatory_references", {})
    reference_found = rr.get("reference_found", {})
    reference_evidence = rr.get("reference_evidence", {})
    searched_files = rr.get("searched_files", [])
    docx = rr.get("docx", {}) or {}
    docx_note = ""
    if docx:
        docx_note = " Документы docx: " + "; ".join(
            f"{rel} — {'все 6 ссылок присутствуют' if d.get('all_six_present') else 'не все ссылки найдены'}" for rel, d in docx.items()
        ) + "."

    if rr.get("all_six_present"):
        return AnalysisResult(
            requirement_id="IB-06", requirement_text=requirement_text, status="pass",
            summary=f"Все 6 требуемых ссылок на нормативные акты найдены в {', '.join(searched_files) or 'документации'}.{docx_note}",
            checked_files=list(searched_files) + list(docx.keys()), analysis_mode="deterministic",
        )

    violations: list[Violation] = []
    for key, found in reference_found.items():
        if found:
            continue
        evidence_list = reference_evidence.get(key, [])
        act = requirements_ru.REGULATORY_ACTS_RU.get(key, key)
        if evidence_list:
            first = evidence_list[0]
            location = {"file": first["file"], "line": first["line"], "function": None}
            snippet = first["text"]
        else:
            location = {"file": searched_files[0] if searched_files else None, "line": None, "function": None}
            snippet = ""
        violations.append(Violation(
            location=location,
            justification=f"Ссылка на «{act}» не найдена ни в одном из проверенных документов ({', '.join(searched_files) or 'файлы документации не найдены'}).",
            severity="medium", recommendation=f"Добавить в раздел нормативных источников README наименование и ссылку: {act}.",
            evidence_snippet=snippet, source="rule:ib06.reference_missing", confidence="confirmed", rule_id="ib06.reference_missing",
            spec_refs=["ТЗ 4.5.6", "ТЗ 3.1"],
        ))

    return AnalysisResult(
        requirement_id="IB-06", requirement_text=requirement_text, status="violation",
        summary=f"Отсутствуют {len(violations)} из 6 требуемых ссылок на нормативные акты.{docx_note}",
        violations=violations, checked_files=list(searched_files) + list(docx.keys()), analysis_mode="deterministic",
    )


def rules_only_result(requirement_id: str, project_root: Path, rule_findings: list, checked: list[str] | None = None,
                      limitations: list[str] | None = None, reason: str = "LLM не использовалась") -> AnalysisResult:
    """Результат по требованию без модели: только детерминированные правила."""
    violations = [rule_finding_to_violation(project_root, rf) for rf in rule_findings]
    status = "violation" if violations else "pass"
    summary = f"{reason}: применены только детерминированные правила (перечень проверенного — ниже)."
    return AnalysisResult(
        requirement_id=requirement_id, requirement_text=IB_REQUIREMENTS[requirement_id], status=status,
        summary=summary, violations=violations, analysis_mode="rules-only",
        analysis_warning=None if violations else (f"{reason}; отсутствие нарушений по правилам не гарантирует полноту проверки" if limitations else None),
    )


def analyze_requirement(
    requirement_id: str,
    index: dict,
    client: LLMClient,
    project_root: Path,
    rule_findings: list | None = None,
    source_budget_chars: int = DEFAULT_SOURCE_BUDGET_CHARS,
    max_rounds: int = 2,
    include_sources: bool = True,
    deadline: float | None = None,
) -> AnalysisResult:
    if requirement_id not in IB_REQUIREMENTS:
        raise ValueError(f"unknown requirement id {requirement_id!r}")
    if requirement_id not in EVIDENCE_BUILDERS:
        raise NotImplementedError(f"evidence builder for {requirement_id} not implemented yet")

    requirement_text = IB_REQUIREMENTS[requirement_id]
    rule_findings = list(rule_findings or [])
    rule_dicts = []
    for i, rf in enumerate(rule_findings, start=1):
        d = rf.to_dict() if hasattr(rf, "to_dict") else dict(rf)
        d = {"id": f"RF-{i}", **d}
        rule_dicts.append(d)
    evidence = EVIDENCE_BUILDERS[requirement_id](index)
    if include_sources:
        evidence = attach_sources(evidence, index, project_root, requirement_id, source_budget_chars)
    known_locations = collect_known_locations(evidence)

    raw = ""
    parsed: dict | None = None
    rounds = 0
    note = None
    json_retry_used = False
    first_failure = None
    while rounds < max_rounds:
        rounds += 1
        user_prompt = build_user_prompt(requirement_id, requirement_text, evidence, rule_dicts, rounds, note)
        raw = client.complete(SYSTEM_PROMPT, user_prompt)
        try:
            parsed = extract_json_object(raw)
        except json.JSONDecodeError as exc:
            meta = raw.describe() if hasattr(raw, "describe") else f"символов ответа={len(str(raw).strip())}"
            if not json_retry_used and (deadline is None or time.monotonic() < deadline):
                # один повтор: пустой/обрезанный/не-JSON ответ — строгая инструкция, при обрезке по длине — меньше исходников
                json_retry_used = True
                first_failure = f"{exc} ({meta})"
                if getattr(raw, "finish_reason", None) == "length" and include_sources:
                    sent = sum(len(v["content"]) for v in (evidence.get("source_files") or {}).values())
                    evidence = attach_sources(EVIDENCE_BUILDERS[requirement_id](index), index, project_root,
                                              requirement_id, max(4000, min(source_budget_chars, sent) // 2))
                    known_locations = collect_known_locations(evidence)
                note = ("предыдущий ответ непригоден (" + meta + "). Не рассуждай вслух: верни ТОЛЬКО один JSON-объект "
                        "по схеме из системной подсказки, без текста до или после него.")
                rounds -= 1
                continue
            reason = (f"модель не дала пригодного ответа: {exc} ({meta})"
                      + (f"; первый ответ тоже непригоден: {first_failure}" if first_failure else "")
                      + " — требование оценено только детерминированными правилами")
            result = AnalysisResult(
                requirement_id=requirement_id, requirement_text=requirement_text, status="insufficient_data", summary="",
                insufficient_data_reason=reason, raw_model_output=str(raw), parse_error=str(exc), llm_rounds=rounds,
                json_retry_used=json_retry_used, model_failure=reason,
            )
            result.violations = [rule_finding_to_violation(project_root, rf) for rf in rule_findings]
            if result.violations:
                # нарушение подтверждено правилами; сбой модели — отдельное предупреждение, не «недостаточно данных»
                result.status = "violation"
                result.insufficient_data_reason = None
                result.analysis_warning = reason
            return result
        need = parsed.get("need_files") if isinstance(parsed, dict) else None
        if need and isinstance(need, list) and rounds < max_rounds and include_sources and (deadline is None or time.monotonic() < deadline):
            wanted = [x for x in need if isinstance(x, str)]
            before = set(evidence.get("source_files") or {})
            evidence = attach_sources(evidence, index, project_root, requirement_id, source_budget_chars + EXTRA_ROUND_BUDGET_CHARS, extra=wanted)
            added = sorted(set(evidence.get("source_files") or {}) - before)
            if not added:
                break
            known_locations = collect_known_locations(evidence)
            note = f"по твоему запросу добавлены файлы: {added}. Файлы, которых нет в проекте, запросить нельзя. Дай окончательный ответ."
            continue
        break

    assert parsed is not None
    claimed_status = parsed.get("status")
    summary = str(parsed.get("summary", "") or "")
    raw_violations = parsed.get("violations") or []
    checked_files = [x for x in (parsed.get("checked_files") or []) if isinstance(x, str)]

    kept: list[Violation] = []
    rejected: list[RejectedCandidate] = []
    for v in raw_violations:
        loc = v.get("location") if isinstance(v, dict) else None
        file = loc.get("file") if isinstance(loc, dict) else None
        line = loc.get("line") if isinstance(loc, dict) else None
        if isinstance(line, str) and line.isdigit():
            line = int(line)
        if not file or not isinstance(line, int):
            rejected.append(RejectedCandidate(v, "нет корректного местоположения (file/line обязательны)"))
            continue
        if (file, line) not in known_locations:
            rejected.append(RejectedCandidate(v, f"местоположение ({file}:{line}) отсутствует в переданных модели данных — вероятная галлюцинация"))
            continue
        snippet = smart_snippet(project_root, file, line)
        if snippet is None:
            rejected.append(RejectedCandidate(v, f"местоположение ({file}:{line}) не соответствует реальной строке файла"))
            continue
        severity = v.get("severity")
        if severity not in ALLOWED_SEVERITIES:
            severity = DEFAULT_SEVERITY
        confidence = v.get("confidence") if v.get("confidence") in ("confirmed", "likely") else "likely"
        kept.append(Violation(
            location={"file": file, "line": line, "function": loc.get("function")},
            justification=str(v.get("justification", "") or ""), severity=severity,
            recommendation=str(v.get("recommendation", "") or ""), evidence_snippet=snippet,
            source="llm", confidence=confidence,
        ))

    # --- слияние с правилами ---
    rule_violations = [rule_finding_to_violation(project_root, rf) for rf in rule_findings]
    reviews = {str(r.get("id")): r for r in (parsed.get("rule_findings_review") or []) if isinstance(r, dict)}
    disputed: list[dict] = []
    final_rules: list[Violation] = []
    for i, rv in enumerate(rule_violations, start=1):
        review = reviews.get(f"RF-{i}")
        if review:
            rv.llm_comment = str(review.get("comment") or "") or None
            ce = review.get("counter_evidence")
            if review.get("verdict") == "dispute" and rv.confidence == "likely" and isinstance(ce, dict) \
                    and (ce.get("file"), ce.get("line")) in known_locations:
                snippet = extract_snippet(project_root, ce["file"], ce["line"]) or ""
                disputed.append({
                    "rule_id": rv.rule_id, "location": rv.location, "justification": rv.justification,
                    "counter_evidence": {"file": ce["file"], "line": ce["line"], "snippet": snippet},
                    "comment": rv.llm_comment,
                })
                continue
            if review.get("verdict") == "confirm":
                rv.confidence = "confirmed"
        final_rules.append(rv)
    merged: list[Violation] = list(final_rules)
    for lv in kept:
        dup = next((rv for rv in merged if _same_place(rv.location, lv.location)), None)
        via_related = False
        if dup is None:
            # то же место уже перечислено в related_locations находки правил этого требования
            # (например, ИБ-07: «чтение не журналируется» со списком маршрутов) — не отдельное нарушение
            dup = next((rv for rv in merged if rv.source.startswith("rule")
                        and any(_same_place(rl, lv.location) for rl in (rv.related_locations or []) if isinstance(rl, dict))), None)
            via_related = dup is not None
        if dup is not None:
            dup.source = "rule+llm" if dup.source.startswith("rule") else dup.source
            if lv.justification and lv.justification not in dup.justification:
                note = (f"[{lv.location.get('file')}:{lv.location.get('line')}] " if via_related else "") + lv.justification
                dup.llm_comment = (dup.llm_comment + " " if dup.llm_comment else "") + note
            if dup.confidence != "confirmed" and lv.confidence == "confirmed":
                dup.confidence = "confirmed"
            continue
        merged.append(lv)

    spec_gaps: list[dict] = []
    for g in parsed.get("spec_gaps") or []:
        if not isinstance(g, dict):
            continue
        loc = g.get("location") if isinstance(g.get("location"), dict) else {}
        file, line = loc.get("file"), loc.get("line")
        if isinstance(line, str) and line.isdigit():
            line = int(line)
        if not file or not isinstance(line, int) or (file, line) not in known_locations:
            continue
        spec_gaps.append({
            "category": g.get("category") or "other",
            "description": str(g.get("description", "") or ""),
            "location": {"file": file, "line": line, "function": loc.get("function")},
            "severity": g.get("severity") if g.get("severity") in ALLOWED_SEVERITIES else None,
            "source": "llm", "requirement_context": requirement_id,
        })

    known_status = claimed_status in ("pass", "violation", "insufficient_data")
    unknown_note = (f"модель вернула нераспознанный статус {claimed_status!r} (допустимы только "
                    f"\"pass\", \"violation\", \"insufficient_data\") — ответ не принят как «соответствует»")
    analysis_warning = None
    if merged:
        final_status = "violation"
        insufficient_reason = None
        if not known_status:
            analysis_warning = unknown_note + "; статус «нарушено» установлен по подтверждённым находкам"
    elif not known_status:
        # никогда не превращать неизвестный/отсутствующий статус в тихое «соответствует»
        final_status = "insufficient_data"
        insufficient_reason = unknown_note
    elif claimed_status == "violation":
        final_status = "insufficient_data"
        insufficient_reason = (f"модель заявила нарушения по {requirement_id}, но ни одно не привязано к реальному месту в переданных данных ({len(rejected)} отклонено)"
                               if rejected else f"модель заявила status=\"violation\" для {requirement_id}, но список нарушений пуст")
    elif claimed_status == "insufficient_data":
        final_status = "insufficient_data"
        insufficient_reason = parsed.get("insufficient_data_reason") or "модель сообщила о недостатке данных без указания причины"
    else:  # claimed_status == "pass"
        final_status = "pass"
        insufficient_reason = None

    return AnalysisResult(
        requirement_id=requirement_id, requirement_text=requirement_text, status=final_status, summary=summary,
        violations=merged, rejected=rejected, insufficient_data_reason=insufficient_reason, raw_model_output=raw,
        spec_gaps=spec_gaps, disputed=disputed, checked_files=checked_files, llm_rounds=rounds, analysis_mode="llm",
        json_retry_used=json_retry_used, analysis_warning=analysis_warning,
    )
