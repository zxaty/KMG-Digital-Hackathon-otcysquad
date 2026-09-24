"""Детерминированные правила по Требованиям ИБ-01…ИБ-08 (модуль 3а).

Слой «страховки» поверх index.json (модуль 2) и исходников проекта:
очевидные нарушения (флаги конфигурации, маршрут без проверки роли,
выгрузка без аудита, обход сигналов аудита, отсутствие журнала СУБД…)
находятся без обращения к модели, воспроизводимо и с точной привязкой
file:line. LLM (analyzer.py) получает эти находки как установленные
факты, подтверждает/уточняет их и ищет то, что правилам недоступно.

Принципы:
- каждое правило возвращает только находки с реальным file:line
  (строка проверяется по файлу на диске — см. Project.find_line);
- правило, которому не хватает данных, пишет ограничение (limitations),
  а не молчит и не выдумывает;
- ничего не выполняется: только ast/regex/json/zip над файлами.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class RuleFinding:
    requirement_id: str
    rule_id: str
    file: str
    line: int | None
    function: str | None
    justification: str
    severity: str
    recommendation: str
    confidence: str = "confirmed"          # confirmed | likely
    related_locations: list[dict] = field(default_factory=list)
    spec_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuleOutcome:
    findings: list[RuleFinding] = field(default_factory=list)
    additional: list[dict] = field(default_factory=list)      # вне ИБ-01…08, пайплайн не блокируют
    limitations: list[str] = field(default_factory=list)
    checked: dict[str, list[str]] = field(default_factory=dict)  # requirement_id -> что именно проверено

    def add(self, f: RuleFinding):
        self.findings.append(f)

    def note_checked(self, rid: str, what: str):
        self.checked.setdefault(rid, []).append(what)


# ---------------------------------------------------------------------------
# Доступ к исходникам
# ---------------------------------------------------------------------------

EXCLUDE_DIR_PARTS = {"migrations", "licenses", ".venv", "venv", "node_modules", "agent", "__pycache__", ".git", "runtime", ".claude"}


class Project:
    def __init__(self, root: Path, index: dict):
        self.root = Path(root)
        self.index = index
        self._lines: dict[str, list[str]] = {}
        self._ast: dict[str, ast.Module | None] = {}
        roots = index.get("meta", {}).get("search_roots") or [str(root)]
        self.search_roots = [Path(r) for r in roots]

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return str(path)

    def exists(self, rel: str) -> bool:
        return (self.root / rel).is_file()

    def lines(self, rel: str) -> list[str]:
        if rel not in self._lines:
            p = self.root / rel
            try:
                self._lines[rel] = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                self._lines[rel] = []
        return self._lines[rel]

    def text(self, rel: str) -> str:
        return "\n".join(self.lines(rel))

    def tree(self, rel: str) -> ast.Module | None:
        if rel not in self._ast:
            try:
                self._ast[rel] = ast.parse(self.text(rel), filename=rel)
            except Exception:
                self._ast[rel] = None
        return self._ast[rel]

    def find_line(self, rel: str, pattern: str, flags=0, start: int = 1) -> int | None:
        rx = re.compile(pattern, flags)
        for i, line in enumerate(self.lines(rel), start=1):
            if i >= start and rx.search(line):
                return i
        return None

    def py_files(self) -> list[str]:
        out: list[str] = []
        seen: set[Path] = set()
        for base in self.search_roots:
            for p in sorted(base.rglob("*.py")):
                if p in seen or any(part in EXCLUDE_DIR_PARTS for part in p.relative_to(base).parts):
                    continue
                seen.add(p)
                out.append(self.rel(p))
        return out

    def module_file(self, dotted: str) -> str | None:
        parts = dotted.split(".")
        for base in self.search_roots:
            cand = base.joinpath(*parts)
            for p in (cand.with_suffix(".py"), cand / "__init__.py"):
                if p.is_file():
                    return self.rel(p)
        return None

    def function_source(self, rel: str, name: str) -> tuple[int, str] | None:
        """(lineno, source) функции/класса верхнего уровня или вложенной с таким именем."""
        tree = self.tree(rel)
        if tree is None:
            return None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
                try:
                    seg = ast.get_source_segment(self.text(rel), node) or ""
                except Exception:
                    seg = ""
                return node.lineno, seg
        return None

    def setting(self, key: str) -> dict | None:
        return self.index.get("settings", {}).get(key)

    def setting_value(self, key: str, default=None):
        entry = self.setting(key)
        if entry and entry.get("resolved"):
            return entry.get("value")
        return default

    def settings_file(self) -> str | None:
        return self.index.get("meta", {}).get("settings_file")

    def setting_line(self, key: str) -> int | None:
        entry = self.setting(key)
        return entry.get("line") if entry else None


# ---------------------------------------------------------------------------
# Классификация защитных механизмов маршрута (общая для ИБ-01/02/08)
# ---------------------------------------------------------------------------

ADMIN_ROLE_RE = re.compile(r"""role\s*(==|in)\s*[\(\[\{]?\s*['"]administrator['"]|role\s*==\s*Role\.ADMIN|\.is_admin\b|has_role\(\s*['"]administrator['"]""", re.I)
WEAK_FLAG_RE = re.compile(r"\bis_staff\b|\bis_superuser\b|staff_member_required|user_passes_test\(\s*lambda\s+\w+\s*:\s*\w+\.is_(?:staff|superuser)")
AUTH_NAMES = ("login_required", "permission_required", "user_passes_test", "staff_member_required",
              "LoginRequiredMixin", "IsAuthenticated", "authentication_classes", "permission_classes", "api_view")
TOKEN_AUTH_RE = re.compile(r"Authorization|Bearer|token_user\(|authenticate\(|request\.auth\b|TokenAuthentication|JWTAuthentication|signing\.loads\(|jwt\.decode\(")
PUBLIC_ROUTE_RE = re.compile(r"^(login/?|logout/?|accounts/login/?|accounts/logout/?|password_reset|reset/|static/|favicon|robots\.txt|healthz?/?|health/?|ping/?|i18n|jsi18n|set_language|\.well-known)")
PUBLIC_VIEW_RE = re.compile(r"LoginView|LogoutView|PasswordReset|login_view|^login$|^logout$|health|ping|favicon|robots")


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _uniq(items) -> list:
    out = []
    for x in items:
        if x not in out:
            out.append(x)
    return out


def _decorators_text(r: dict) -> str:
    names = _uniq(_short(n) for n in (r.get("url_level_wrappers") or []) + (r.get("decorators") or []))
    return ", ".join(names) or "нет"


def _dedupe_routes(rs: list[dict]) -> list[dict]:
    seen, out = set(), []
    for r in rs:
        key = (r.get("view_file"), r.get("view_line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


class GuardResolver:
    """Определяет, что реально проверяет цепочка декораторов/обёрток/вызовов маршрута."""

    def __init__(self, project: Project):
        self.project = project
        self.defs: dict[str, dict] = project.index.get("guard_definitions", {}) or {}

    def _source_matches(self, name: str, rx: re.Pattern, depth: int = 3, seen: set | None = None) -> str | None:
        """Возвращает имя guard-функции, в исходнике которой найден паттерн (транзитивно)."""
        seen = seen or set()
        if name in seen or depth < 0:
            return None
        seen.add(name)
        d = self.defs.get(name)
        if not d or not d.get("source"):
            return None
        src = d["source"]
        if rx.search(src):
            return name
        # переход к вызываемым внутри guard-функциям, известным индексу
        for other in self.defs:
            if other == name:
                continue
            if re.search(r"\b" + re.escape(_short(other)) + r"\s*\(", src):
                hit = self._source_matches(other, rx, depth - 1, seen)
                if hit:
                    return hit
        return None

    def classify(self, route: dict) -> dict:
        names = list(route.get("url_level_wrappers") or []) + list(route.get("decorators") or [])
        body_calls = [g["name"] for g in (route.get("body_guard_calls") or []) if g.get("kind") == "call"]
        compares = [g["source"] for g in (route.get("body_guard_calls") or []) if g.get("kind") == "compare"]
        view_src = ""
        if route.get("view_file") and route.get("view_function"):
            fs = self.project.function_source(route["view_file"], route["view_function"])
            view_src = fs[1] if fs else ""

        admin_by: str | None = None
        for n in names + body_calls:
            hit = self._source_matches(n, ADMIN_ROLE_RE)
            if hit:
                admin_by = hit
                break
        if not admin_by and any(ADMIN_ROLE_RE.search(c) for c in compares):
            admin_by = f"{route.get('view_function')} (проверка в теле представления)"

        weak_by: str | None = None
        for n in names + body_calls:
            hit = self._source_matches(n, WEAK_FLAG_RE)
            if hit:
                weak_by = hit
                break
        if not weak_by and any(WEAK_FLAG_RE.search(c) for c in compares):
            weak_by = f"{route.get('view_function')} (проверка в теле представления)"

        authenticated = any(_short(n) in AUTH_NAMES for n in names) or any(
            self._source_matches(n, re.compile(r"login_required|is_authenticated")) for n in names + body_calls
        )
        token_auth = bool(TOKEN_AUTH_RE.search(view_src)) or any(
            self._source_matches(n, TOKEN_AUTH_RE) for n in body_calls
        )
        if not token_auth:
            # вызов в теле функции из того же модуля, содержащей проверку токена (один переход)
            for call_name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", view_src):
                if route.get("view_file") and call_name not in ("len", "str", "int", "dict", "list"):
                    fs = self.project.function_source(route["view_file"], call_name)
                    if fs and TOKEN_AUTH_RE.search(fs[1]):
                        token_auth = True
                        break
        level = "none"
        if admin_by:
            level = "admin_role"
        elif weak_by:
            level = "weak_flag"
        elif authenticated or token_auth:
            level = "authenticated"
        return {
            "level": level, "admin_by": admin_by, "weak_by": weak_by,
            "authenticated": authenticated, "token_auth": token_auth, "view_source": view_src,
        }


def _guard_def_location(resolver: GuardResolver, name: str | None) -> tuple[str | None, int | None]:
    if not name:
        return None, None
    d = resolver.defs.get(name)
    if not d:
        return None, None
    return d.get("file"), d.get("line")


# ---------------------------------------------------------------------------
# ИБ-01. Разграничение доступа к административному функционалу
# ---------------------------------------------------------------------------

ADMIN_ROUTE_RE = re.compile(r"manage|admin|users?/|/roles?/|permission|reset_password|grant|revoke|settings|config|system", re.I)
OWN_PASSWORD_RE = re.compile(r"accounts/password|password_change|PasswordChangeView", re.I)
EXPORT_RE = re.compile(r"export|\.csv|\.xlsx?$|download|dump|people|directory|справочник", re.I)


def check_ib01(p: Project, out: RuleOutcome, resolver: GuardResolver):
    routes = p.index.get("routes", [])
    if not routes:
        out.limitations.append("ИБ-01: маршруты проекта не удалось разобрать статически (urlpatterns не найдены) — правила по ИБ-01 не применялись.")
        return
    admin_routes = []
    for r in routes:
        blob = f"{r.get('pattern','')} {r.get('name','') or ''} {r.get('view_function','') or ''}"
        if OWN_PASSWORD_RE.search(blob) or EXPORT_RE.search(blob):
            continue
        if ADMIN_ROUTE_RE.search(blob):
            admin_routes.append(r)
    out.note_checked("IB-01", f"проверено маршрутов: {len(routes)}, из них административных по назначению: {len(admin_routes)}")

    weak_groups: dict[str, list[dict]] = {}
    for r in admin_routes:
        cls = resolver.classify(r)
        loc_file, loc_line = r.get("view_file"), r.get("view_line")
        if cls["level"] == "admin_role":
            continue
        if cls["level"] == "weak_flag":
            weak_groups.setdefault(cls["weak_by"], []).append(r)
            continue
        if not loc_file:
            continue
        sev = "critical" if cls["level"] == "none" else "high"
        what = ("без какой-либо проверки аутентификации и роли" if cls["level"] == "none"
                else "только с проверкой аутентификации (login_required/токен) — роль «администратор» на сервере не проверяется")
        out.add(RuleFinding(
            requirement_id="IB-01", rule_id="ib01.admin_route_without_role_check",
            file=loc_file, line=loc_line, function=r.get("view_function"),
            justification=(f"Маршрут `{r.get('pattern')}` ({r.get('view_function')}) относится к административным функциям "
                           f"(управление пользователями/ролями/очередями/настройками), но доступен {what}. "
                           f"Декораторы/обёртки: {_decorators_text(r)}."),
            severity=sev,
            recommendation="Применить к представлению серверную проверку роли администратора (единый декоратор, проверяющий request.user.role == 'administrator' на каждом запросе) до чтения и изменения данных.",
            spec_refs=["ТЗ 4.5.1", "ТС 4.3.2", "ТС 4.3.3"],
        ))
    for guard_name, rs in weak_groups.items():
        gfile, gline = _guard_def_location(resolver, guard_name)
        if not gfile:
            gfile, gline = rs[0].get("view_file"), rs[0].get("view_line")
        related = [{"file": r.get("view_file"), "line": r.get("view_line"), "function": r.get("view_function"), "pattern": r.get("pattern")} for r in rs]
        out.add(RuleFinding(
            requirement_id="IB-01", rule_id="ib01.admin_guard_checks_technical_flag",
            file=gfile, line=gline, function=_short(guard_name),
            justification=(f"Защитный механизм `{_short(guard_name)}` ограничивает административные маршруты "
                           f"({', '.join(r.get('pattern','') for r in rs)}) по техническому признаку учётной записи "
                           f"(is_staff/is_superuser), а не по роли «администратор». Признак is_staff в проекте присваивается и операторам "
                           f"(см. создание/смену роли пользователя), поэтому оператор получает доступ к административному интерфейсу: "
                           f"видит справочник всех пользователей с ПД, может менять роли (в т.ч. назначить себя администратором), выдавать права на очереди и сбрасывать чужие пароли. "
                           f"ТС 4.3.2 прямо запрещает предоставлять административные полномочия по техническим признакам платформы."),
            severity="high",
            recommendation="Заменить проверку is_staff на проверку роли: использовать тот же механизм, что и в admin_required (role == 'administrator'), для всех административных маршрутов, включая API управления очередями.",
            related_locations=related,
            spec_refs=["ТЗ 4.5.1", "ТС 4.3.2", "ТС 1.11"],
        ))
    # Встроенная админ-панель Django (доступ по is_staff)
    apps = p.setting_value("INSTALLED_APPS") or []
    if any(isinstance(a, str) and a.startswith("django.contrib.admin") for a in apps):
        admin_routes_dj = [r for r in routes if "admin.site" in (r.get("target") or "")]
        sfile, sline = p.settings_file(), p.setting_line("INSTALLED_APPS")
        if admin_routes_dj and sfile:
            r0 = admin_routes_dj[0]
            out.add(RuleFinding(
                requirement_id="IB-01", rule_id="ib01.django_admin_enabled",
                file=r0.get("source_file") or sfile, line=r0.get("line") or sline, function=None,
                justification="Подключена встроенная админ-панель Django (django.contrib.admin, admin.site.urls): доступ к ней определяется признаком is_staff, а не ролью «администратор».",
                severity="high",
                recommendation="Отключить django.contrib.admin либо ограничить admin.site доступом по роли (переопределить admin.site.has_permission).",
                spec_refs=["ТЗ 4.5.1", "ТС 4.3.2"],
            ))


# ---------------------------------------------------------------------------
# ИБ-02. Проверка сессии/токена на сервере при каждом обращении
# ---------------------------------------------------------------------------

def check_ib02(p: Project, out: RuleOutcome, resolver: GuardResolver):
    routes = p.index.get("routes", [])
    if not routes:
        out.limitations.append("ИБ-02: маршруты проекта не удалось разобрать статически — правила по ИБ-02 не применялись.")
        return
    out.note_checked("IB-02", f"проверено маршрутов на наличие серверной проверки сессии/токена: {len(routes)}")
    for r in routes:
        blob = f"{r.get('pattern','')} {r.get('view_function','') or ''} {r.get('target','') or ''}"
        if PUBLIC_ROUTE_RE.search(r.get("pattern", "") or "") or PUBLIC_VIEW_RE.search(blob):
            continue
        cls = resolver.classify(r)
        if cls["level"] != "none":
            continue
        if r.get("is_class_based") and not r.get("view_file"):
            out.limitations.append(f"ИБ-02: класс-представление `{r.get('target')}` для `{r.get('pattern')}` не найдено в проекте (внешняя библиотека) — защита не установлена статически.")
            continue
        if not r.get("view_file"):
            continue
        src = cls["view_source"]
        returns_data = bool(re.search(r"JsonResponse|HttpResponse|render\(|FileResponse|Response\(|serialize", src))
        exposes_pii = bool(re.search(r"email|last_name|first_name|username|phone", src))
        if not exposes_pii:
            for call_name in set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", src)):
                fs = p.function_source(r["view_file"], call_name)
                if fs and re.search(r"email|last_name|first_name|username|phone", fs[1]):
                    exposes_pii = True
                    break
        out.add(RuleFinding(
            requirement_id="IB-02", rule_id="ib02.route_without_auth",
            file=r["view_file"], line=r.get("view_line"), function=r.get("view_function"),
            justification=(f"Конечная точка `{r.get('pattern')}` ({r.get('view_function')}) не защищена ни проверкой сессии "
                           f"(login_required/middleware), ни проверкой токена: в urls.py нет обёртки, у представления нет "
                           f"декоратора аутентификации, в теле нет проверки заголовка Authorization. "
                           + ("Представление возвращает данные" + (" с персональными сведениями (email)" if exposes_pii else "") +
                              " любому анонимному клиенту." if returns_data else "")),
            severity="critical" if returns_data else "high",
            recommendation="Добавить серверную проверку сессии или токена (единый механизм, как у остальных защищённых маршрутов) и ограничить выборку областью данных пользователя.",
            spec_refs=["ТЗ 4.5.2", "ТС 4.4.1", "ТС 4.4.3", "ТС 4.3.9"],
        ))
    # Проверка токена: срок действия
    for v in p.index.get("token_lifecycle", {}).get("validators", []):
        fs = p.function_source(v["file"], v["function"]) if v.get("file") else None
        if not fs:
            continue
        lineno, src = fs
        if "signing.loads(" in src and "max_age" not in src and not v.get("checks_exp_claim"):
            call_line = p.find_line(v["file"], r"signing\.loads\(", start=lineno) or lineno
            out.add(RuleFinding(
                requirement_id="IB-02", rule_id="ib02.token_expiry_not_enforced",
                file=v["file"], line=call_line, function=v["function"],
                justification=(f"Функция `{v['function']}` проверяет только подпись токена (signing.loads без max_age) и не "
                               f"сравнивает поле exp с текущим временем: истёкший токен принимается как действительный, "
                               f"т.е. валидность токена на сервере проверяется не полностью (ТС 4.4.3: отклонять истёкшие сессии/токены)."),
                severity="high",
                recommendation="Передавать max_age в signing.loads либо явно проверять data['exp'] > time.time(); при выходе из системы, смене пароля или роли — отзывать выданные токены.",
                spec_refs=["ТЗ 4.5.2", "ТС 4.4.3", "ТС 4.4.7"],
            ))
        if re.search(r"jwt\.decode\([^)]*verify(_signature)?\s*[=:]\s*False", src, re.S) or re.search(r"['\"]verify_exp['\"]\s*:\s*False", src):
            out.add(RuleFinding(
                requirement_id="IB-02", rule_id="ib02.jwt_verification_disabled",
                file=v["file"], line=lineno, function=v["function"],
                justification=f"В `{v['function']}` отключена проверка подписи или срока действия JWT.",
                severity="critical",
                recommendation="Включить проверку подписи и exp при декодировании JWT.",
                spec_refs=["ТЗ 4.5.2", "ТС 4.4.7"],
            ))
    # Сессионные параметры — вне ядра ИБ-02, но по ТС; не блокируют
    age = p.setting_value("SESSION_COOKIE_AGE")
    if isinstance(age, int) and age > 3600 and p.settings_file():
        out.additional.append({
            "category": "session-auth-detail", "severity": "medium",
            "description": f"SESSION_COOKIE_AGE = {age} с: срок действия сессии превышает 60 минут, требуемые ТС 4.4.2.",
            "location": {"file": p.settings_file(), "line": p.setting_line("SESSION_COOKIE_AGE")},
            "spec_refs": ["ТС 4.4.2"],
        })
    if p.setting_value("SESSION_COOKIE_HTTPONLY", True) is False and p.settings_file():
        out.additional.append({
            "category": "session-auth-detail", "severity": "medium",
            "description": "SESSION_COOKIE_HTTPONLY = False: идентификатор сессии доступен сценариям браузера (ТС 4.4.2).",
            "location": {"file": p.settings_file(), "line": p.setting_line("SESSION_COOKIE_HTTPONLY")},
            "spec_refs": ["ТС 4.4.2"],
        })


# ---------------------------------------------------------------------------
# ИБ-03. Защита канала передачи данных
# ---------------------------------------------------------------------------

WEAK_CIPHER_RE = re.compile(r"NULL|EXPORT|RC4|RC2|DES|MD5|aNULL|eNULL|ADH|AECDH|PSK|SRP|IDEA|SEED|CAMELLIA-.*-SHA$", re.I)
CIPHER_GROUP_RE = re.compile(r"^(ALL|DEFAULT|COMPLEMENTOFDEFAULT|COMPLEMENTOFALL|LOW|MEDIUM|HIGH|SSLv3|TLSv1|TLSv1\.2|kRSA|aRSA|RSA|AES|AES128|AES256|SHA|SHA1|SHA256|SHA384)$", re.I)
TLS13_SUITES = {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256"}


def evaluate_cipher(suite: str) -> str | None:
    """None — стойкий шифронабор; иначе краткая причина, почему слабый."""
    s = suite.strip()
    if not s or s.startswith("!") or s.startswith("-") or s.startswith("+"):
        return None
    if s.startswith("@"):
        return None
    if s in TLS13_SUITES:
        return None
    if CIPHER_GROUP_RE.match(s):
        return "групповое имя OpenSSL, включающее слабые наборы"
    if WEAK_CIPHER_RE.search(s):
        return "устаревший/слабый алгоритм"
    aead = bool(re.search(r"GCM|CCM|CHACHA20|POLY1305", s, re.I))
    ephemeral = s.upper().startswith(("ECDHE", "DHE", "EDH", "ECDH-", "DH-"))
    reasons = []
    if not ephemeral:
        reasons.append("обмен ключами RSA без эфемерности (ECDHE)")
    if not aead:
        reasons.append("режим CBC/без AEAD")
    if re.search(r"-SHA$", s):
        reasons.append("HMAC-SHA1")
    return "; ".join(reasons) if reasons else None


def check_ib03(p: Project, out: RuleOutcome):
    sfile = p.settings_file()
    checks = [
        ("SESSION_COOKIE_SECURE", False, "сессионная cookie может передаваться по незащищённому HTTP (нет флага Secure)", "high", "SESSION_COOKIE_SECURE = True"),
        ("CSRF_COOKIE_SECURE", False, "CSRF-cookie может передаваться по незащищённому HTTP (нет флага Secure)", "high", "CSRF_COOKIE_SECURE = True"),
        ("SECURE_SSL_REDIRECT", False, "приложение не принуждает к защищённому соединению: запросы по HTTP обслуживаются без перенаправления на HTTPS", "high", "SECURE_SSL_REDIRECT = True (и перенаправление на уровне транспортного модуля)"),
    ]
    if sfile:
        for key, bad, why, sev, fix in checks:
            entry = p.setting(key)
            if entry is None:
                # Django по умолчанию: все три флага False
                continue
            if entry.get("resolved") and entry.get("value") is bad:
                out.add(RuleFinding(
                    requirement_id="IB-03", rule_id=f"ib03.{key.lower()}",
                    file=sfile, line=entry.get("line"), function=key,
                    justification=f"{key} = {entry.get('value')!r}: {why}. Конфигурация допускает передачу данных в незащищённом виде (ТС 4.8.2).",
                    severity=sev,
                    recommendation=f"Установить {fix}.",
                    spec_refs=["ТЗ 4.5.3", "ТС 4.8.2"],
                ))
        hsts = p.setting("SECURE_HSTS_SECONDS")
        if hsts and hsts.get("resolved") and isinstance(hsts.get("value"), int) and hsts["value"] <= 0:
            out.add(RuleFinding(
                requirement_id="IB-03", rule_id="ib03.hsts_disabled",
                file=sfile, line=hsts.get("line"), function="SECURE_HSTS_SECONDS",
                justification="SECURE_HSTS_SECONDS = 0: политика принудительного использования защищённого соединения (HSTS) не объявляется, браузер может обратиться по HTTP (ТС 4.8.2).",
                severity="medium",
                recommendation="Установить SECURE_HSTS_SECONDS (например, 31536000) и SECURE_HSTS_INCLUDE_SUBDOMAINS = True.",
                spec_refs=["ТЗ 4.5.3", "ТС 4.8.2"],
            ))
        out.note_checked("IB-03", "флаги SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE, SECURE_SSL_REDIRECT, SECURE_HSTS_SECONDS в settings")
    else:
        out.limitations.append("ИБ-03: файл настроек Django не найден — флаги защищённых cookie/redirect/HSTS не проверены.")

    # Конфигурации транспортного модуля (*.json в корне: proxy.json и т.п.)
    aux = p.index.get("auxiliary_configs", {}) or {}
    for fname, cfg in aux.items():
        if not isinstance(cfg, dict):
            continue
        keys = {k.lower() for k in cfg}
        if not keys & {"http_redirect", "minimum_tls", "ciphers", "tls", "ssl", "https_port"}:
            continue
        out.note_checked("IB-03", f"конфигурация транспортного модуля {fname}: версия TLS, шифронаборы, перенаправление HTTP")
        if "http_redirect" in cfg and cfg.get("http_redirect") is False:
            line = p.find_line(fname, r'"http_redirect"')
            out.add(RuleFinding(
                requirement_id="IB-03", rule_id="ib03.http_listener_without_redirect",
                file=fname, line=line, function="http_redirect",
                justification=(f"{fname}: \"http_redirect\": false — транспортный модуль принимает запросы на HTTP-порту "
                               f"{cfg.get('http_port', '?')} и проксирует их в приложение как есть, вместо перенаправления на HTTPS. "
                               f"Данные (включая учётные данные и cookie сессии) могут передаваться открытым текстом."),
                severity="critical",
                recommendation="Установить \"http_redirect\": true (ответ 308 на HTTPS-порт) либо не открывать HTTP-слушатель вовсе.",
                spec_refs=["ТЗ 4.5.3", "ТС 4.8.2"],
            ))
        mt = str(cfg.get("minimum_tls", "")).upper().replace(".", "_")
        if mt and mt in ("SSLV2", "SSLV3", "TLSV1", "TLSV1_0", "TLSV1_1", "MINIMUM_SUPPORTED"):
            line = p.find_line(fname, r'"minimum_tls"')
            out.add(RuleFinding(
                requirement_id="IB-03", rule_id="ib03.min_tls_below_1_2",
                file=fname, line=line, function="minimum_tls",
                justification=f"{fname}: minimum_tls = {cfg.get('minimum_tls')!r} — допускаются устаревшие версии протокола ниже TLS 1.2.",
                severity="critical",
                recommendation="Установить \"minimum_tls\": \"TLSv1_2\" или выше.",
                spec_refs=["ТЗ 4.5.3", "ТС 4.8.1"],
            ))
        ciphers = cfg.get("ciphers")
        if isinstance(ciphers, str):
            weak = [(c, evaluate_cipher(c)) for c in ciphers.split(":")]
            weak = [(c, why) for c, why in weak if why]
            if weak:
                line = p.find_line(fname, r'"ciphers"')
                out.add(RuleFinding(
                    requirement_id="IB-03", rule_id="ib03.weak_cipher_suites",
                    file=fname, line=line, function="ciphers",
                    justification=(f"{fname}: в списке шифронаборов присутствуют слабые: "
                                   + "; ".join(f"{c} ({why})" for c, why in weak)
                                   + ". ТС 4.8.1 допускает для TLS 1.2 только наборы с ECDHE и AEAD; наборы с обменом ключами RSA, режимом CBC и HMAC-SHA1 запрещены."),
                    severity="high",
                    recommendation="Оставить только ECDHE+AEAD, например: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305.",
                    spec_refs=["ТЗ 4.5.3", "ТС 4.8.1"],
                ))
    # Код: отключённая проверка сертификатов, устаревшие версии протокола
    patterns = [
        (r"ssl\._create_unverified_context|CERT_NONE|check_hostname\s*=\s*False|verify\s*=\s*False", "отключена проверка подлинности сертификата TLS", "high", "ТС 4.8.3"),
        (r"PROTOCOL_TLSv1(_1)?\b|PROTOCOL_SSLv[23]\b|TLSVersion\.(SSLv3|TLSv1|TLSv1_1)\b|ssl_version\s*=\s*ssl\.PROTOCOL_TLSv1", "используется устаревшая версия протокола SSL/TLS", "critical", "ТС 4.8.1"),
    ]
    for rel in p.py_files():
        text = p.text(rel)
        for rx, why, sev, ref in patterns:
            for m in re.finditer(rx, text):
                line = text.count("\n", 0, m.start()) + 1
                line_text = p.lines(rel)[line - 1] if line - 1 < len(p.lines(rel)) else ""
                if line_text.lstrip().startswith("#"):
                    continue
                out.add(RuleFinding(
                    requirement_id="IB-03", rule_id="ib03.insecure_tls_usage_in_code",
                    file=rel, line=line, function=None,
                    justification=f"{why}: `{line_text.strip()[:160]}`.",
                    severity=sev,
                    recommendation="Включить проверку сертификатов и использовать TLS не ниже 1.2 (ssl.PROTOCOL_TLS_CLIENT/SERVER с minimum_version = TLSv1_2).",
                    spec_refs=["ТЗ 4.5.3", ref],
                ))


# ---------------------------------------------------------------------------
# ИБ-04. Криптографическая защита ПД при хранении
# ---------------------------------------------------------------------------

STRONG_HASHERS = ("Argon2PasswordHasher", "BCryptSHA256PasswordHasher", "BCryptPasswordHasher", "ScryptPasswordHasher")
PII_FIELD_NAMES = {"first_name", "last_name", "middle_name", "patronymic", "surname", "given_name", "full_name", "fio",
                   "email", "username", "login", "phone", "phone_number", "mobile", "iin", "birth_date", "birthday", "address"}
PLAIN_FIELD_TYPES = {"CharField", "EmailField", "TextField"}


def _resolve_hasher(p: Project, dotted: str) -> tuple[str, str | None, int | None, str]:
    """(verdict, file, line, detail): verdict ∈ strong | weak | unknown."""
    short = _short(dotted)
    if dotted.startswith("django.contrib.auth.hashers."):
        return ("strong" if short in STRONG_HASHERS else "weak"), None, None, short
    module, cls = dotted.rsplit(".", 1)
    rel = p.module_file(module)
    if not rel:
        return "unknown", None, None, f"модуль {module} не найден"
    fs = p.function_source(rel, cls)
    if not fs:
        return "unknown", rel, None, f"класс {cls} не найден в {rel}"
    lineno, src = fs
    bases = re.findall(r"class\s+\w+\s*\(([^)]*)\)", src)
    base_names = [b.strip().rsplit(".", 1)[-1] for b in (bases[0].split(",") if bases else [])]
    if any(b in STRONG_HASHERS for b in base_names):
        return "strong", rel, lineno, f"{cls} наследует {', '.join(base_names)}"
    if re.search(r"algorithm\s*=\s*['\"](md5|sha1|sha256|unsalted|crypt)", src, re.I) or any(b in ("MD5PasswordHasher", "SHA1PasswordHasher", "UnsaltedMD5PasswordHasher", "UnsaltedSHA1PasswordHasher", "PBKDF2PasswordHasher", "PBKDF2SHA1PasswordHasher", "CryptPasswordHasher") for b in base_names):
        return "weak", rel, lineno, f"{cls} наследует {', '.join(base_names) or 'BasePasswordHasher'}"
    return "unknown", rel, lineno, f"{cls} наследует {', '.join(base_names) or '?'}"


def check_ib04(p: Project, out: RuleOutcome):
    sfile = p.settings_file()
    hashers = p.setting("PASSWORD_HASHERS")
    if sfile and (hashers is None):
        out.add(RuleFinding(
            requirement_id="IB-04", rule_id="ib04.default_pbkdf2_hasher",
            file=sfile, line=1, function="PASSWORD_HASHERS",
            justification="PASSWORD_HASHERS не задан: Django по умолчанию хеширует пароли PBKDF2-SHA256, тогда как ИБ-04 допускает только bcrypt, argon2 или scrypt.",
            severity="high",
            recommendation="Задать PASSWORD_HASHERS = ['django.contrib.auth.hashers.Argon2PasswordHasher', ...] и установить argon2-cffi.",
            spec_refs=["ТЗ 4.5.4", "ТС 4.5.2"],
        ))
    elif hashers and hashers.get("resolved") and isinstance(hashers.get("value"), list) and hashers["value"]:
        first = hashers["value"][0]
        verdict, hfile, hline, detail = _resolve_hasher(p, first)
        out.note_checked("IB-04", f"основной хешер паролей {first}: {detail}")
        if verdict == "weak":
            out.add(RuleFinding(
                requirement_id="IB-04", rule_id="ib04.weak_password_hasher",
                file=hfile or sfile, line=hline or hashers.get("line"), function=_short(first),
                justification=f"Основной хешер паролей `{first}` ({detail}) не относится к bcrypt/argon2/scrypt — быстрая хеш-функция без адаптивного алгоритма.",
                severity="critical",
                recommendation="Использовать Argon2PasswordHasher/BCryptSHA256PasswordHasher/ScryptPasswordHasher первым в PASSWORD_HASHERS.",
                spec_refs=["ТЗ 4.5.4", "ТС 4.5.2"],
            ))
        elif verdict == "unknown":
            out.limitations.append(f"ИБ-04: алгоритм хешера `{first}` не удалось установить статически ({detail}) — требуется оценка модели.")
    # Обход хеширования при записи пароля
    for hit in p.index.get("password_bypass_writes", []) or []:
        src = hit.get("source", "")
        if re.search(r"make_password\(|set_unusable_password|hasher|\bhashed\b", src):
            continue
        out.add(RuleFinding(
            requirement_id="IB-04", rule_id="ib04.password_written_bypassing_hasher",
            file=hit["file"], line=hit["line"], function=None,
            justification=f"Пароль записывается в обход штатного хеширования ({hit.get('kind')}): `{src[:160]}`.",
            severity="critical",
            recommendation="Использовать user.set_password()/make_password(), чтобы пароль проходил через PASSWORD_HASHERS.",
            spec_refs=["ТЗ 4.5.4", "ТС 4.5.2"],
        ))
    # Фикстуры с открытыми паролями
    for f in p.index.get("inventory", {}).get("files", []):
        if f["category"] != "config" or not f["path"].endswith(".json") or f["size"] > 2_000_000:
            continue
        for i, line in enumerate(p.lines(f["path"]), start=1):
            m = re.search(r'"password"\s*:\s*"([^"]+)"', line)
            if m and not re.match(r"(argon2|bcrypt|scrypt|pbkdf2|\$2[aby]\$|md5\$|sha1\$|!)", m.group(1)):
                out.add(RuleFinding(
                    requirement_id="IB-04", rule_id="ib04.plaintext_password_in_fixture",
                    file=f["path"], line=i, function=None,
                    justification="В файле данных пароль хранится в открытом виде (не хеш bcrypt/argon2/scrypt).",
                    severity="critical",
                    recommendation="Хранить в фикстурах только хеши, полученные штатным хешером, либо задавать пароли при загрузке через set_password().",
                    spec_refs=["ТЗ 4.5.4", "ТС 4.5.2"],
                ))
                break
    # Персональные данные в открытом виде в модели пользователя
    user_model = p.setting_value("AUTH_USER_MODEL")
    engine = str((p.setting_value("DATABASES") or {}).get("default", {}).get("ENGINE", "")) if isinstance(p.setting_value("DATABASES"), dict) else ""
    encrypted_db = bool(re.search(r"sqlcipher|encrypt", engine, re.I))
    models = p.index.get("models", [])
    target = None
    if isinstance(user_model, str) and "." in user_model:
        app_label, cls = user_model.split(".", 1)
        for m in models:
            if m["class_name"] == cls and Path(m["app_dir"]).name == app_label:
                target = m
                break
    if target is not None:
        plain = [f for f in target["fields"] if f["name"].lower() in PII_FIELD_NAMES and _short(f.get("type") or "") in PLAIN_FIELD_TYPES]
        enc = [f for f in target["fields"] if f["name"].lower() in PII_FIELD_NAMES and f.get("type") and re.search(r"encrypt|cipher|secure|protected", f["type"], re.I)]
        out.note_checked("IB-04", f"модель пользователя {user_model}: поля ПД {[f['name'] for f in target['fields'] if f['name'].lower() in PII_FIELD_NAMES]}")
        inherited_plain = []
        if any(_short(b) == "AbstractUser" for b in target.get("bases", [])):
            declared = {f["name"] for f in target["fields"]}
            inherited_plain = [n for n in ("username", "first_name", "last_name", "email") if n not in declared]
        if (plain or inherited_plain) and not encrypted_db:
            names = ", ".join(f"{f['name']} ({_short(f['type'])}, стр. {f['line']})" for f in plain)
            if inherited_plain:
                names += (", " if names else "") + "унаследованы от AbstractUser открытым текстом: " + ", ".join(inherited_plain)
            anchor = None   # якорь — объявление класса модели (фрагмент покажет все поля)
            storage_encrypted = any(AEAD_RE.search(p.text(x)) for x in p.py_files() if "storage" in Path(x).name)
            out.add(RuleFinding(
                requirement_id="IB-04", rule_id="ib04.pii_fields_stored_plaintext",
                file=target["file"], line=anchor["line"] if anchor else target["line"], function=target["class_name"], confidence="likely",
                justification=(f"Персональные данные в модели пользователя `{target['class_name']}` хранятся в БД открытым текстом: {names}. "
                               f"Шифрование на уровне полей (аутентифицированное шифрование, ключ ≥ 256 бит — ТС 4.5.3) или шифрованная СУБД не обнаружены; "
                               f"криптографически защищены только пароль (хеш){' и содержимое вложений (AEAD в модуле хранения)' if storage_encrypted else ''}."),
                severity="high",
                recommendation="Хранить ФИО, логин и e-mail через поля с аутентифицированным шифрованием (AES-256-GCM с ключом из runtime/keys, отдельным от данных); для поиска по логину/e-mail использовать слепой индекс (HMAC).",
                related_locations=[{"file": target["file"], "line": f["line"], "function": f["name"]} for f in plain],
                spec_refs=["ТЗ 4.5.4", "ТС 4.5.1", "ТС 4.5.3"],
            ))
        elif enc:
            out.note_checked("IB-04", f"поля ПД используют шифрующие типы: {[f['name'] for f in enc]}")
    elif sfile:
        apps = p.setting_value("INSTALLED_APPS") or []
        if any(isinstance(a, str) and a == "django.contrib.auth" for a in apps):
            out.add(RuleFinding(
                requirement_id="IB-04", rule_id="ib04.default_user_model_plaintext_pii",
                file=sfile, line=p.setting_line("INSTALLED_APPS"), function="AUTH_USER_MODEL",
                justification="AUTH_USER_MODEL не переопределён: используется стандартная модель django.contrib.auth.User, в которой username, first_name, last_name, email хранятся открытым текстом.",
                severity="high", confidence="likely",
                recommendation="Определить собственную модель пользователя с шифрованием полей ПД.",
                spec_refs=["ТЗ 4.5.4", "ТС 4.5.3"],
            ))
    # Копии ПД в других моделях — не блокирующее замечание
    for m in models:
        if m is target:
            continue
        pii = [f for f in m["fields"] if f["name"].lower() in PII_FIELD_NAMES and _short(f.get("type") or "") in PLAIN_FIELD_TYPES]
        if pii and not encrypted_db:
            out.additional.append({
                "category": "data-handling-detail", "severity": "low",
                "description": f"Модель `{m['class_name']}` хранит копии персональных данных открытым текстом: {', '.join(f['name'] for f in pii)} (ТС 4.5.1 относит копии ПД в обращениях к защищаемым данным).",
                "location": {"file": m["file"], "line": pii[0]["line"], "function": m["class_name"]},
                "spec_refs": ["ТС 4.5.1", "ТС 4.5.3"],
            })


# ---------------------------------------------------------------------------
# ИБ-05. Защита локальных журналов приложения
# ---------------------------------------------------------------------------

AEAD_RE = re.compile(r"AESGCM|AESCCM|ChaCha20Poly1305|Fernet|AESSIV|\.encrypt\(")
FILE_WRITE_RE = re.compile(r"write_bytes\(|write_text\(|open\([^)]*['\"][wa]b?['\"]|\.write\(")
LOG_HINT_RE = re.compile(r"journal|audit|\blog\b|logging|event", re.I)
ACL_CALL_RE = re.compile(r"set_reader_access\((.+?),\s*['\"](none|read|modify)['\"]\)")


def check_ib05(p: Project, out: RuleOutcome):
    writers: list[tuple[str, int, bool]] = []
    for rel in p.py_files():
        text = p.text(rel)
        if not LOG_HINT_RE.search(Path(rel).name + " " + text[:4000]):
            continue
        tree = p.tree(rel)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                seg = ast.get_source_segment(text, node) or ""
                serializes = re.search(r"json\.dumps|\.encode\(|pickle\.dumps|str\(|f['\"]|\.format\(", seg) is not None
                if FILE_WRITE_RE.search(seg) and serializes and re.search(r"journal|audit|log|event|\.evt|\.tmp", seg, re.I) and "collectstatic" not in seg:
                    writers.append((rel, node.lineno, bool(AEAD_RE.search(seg)) or bool(AEAD_RE.search(text))))
    if not writers:
        out.limitations.append("ИБ-05: модуль записи локального журнала приложения не обнаружен статически — статус определяется по оценке модели.")
    else:
        out.note_checked("IB-05", f"функции записи журнала: {[(w[0], w[1]) for w in writers]}")
    for rel, line, encrypted in writers:
        if not encrypted:
            out.add(RuleFinding(
                requirement_id="IB-05", rule_id="ib05.log_written_unencrypted",
                file=rel, line=line, function=None,
                justification="Функция записывает записи локального журнала на диск без шифрования (AEAD/Fernet не используются).",
                severity="high",
                recommendation="Шифровать каждую запись аутентифицированным шифрованием (AES-GCM с уникальным nonce) ключом, недоступным пользователю.",
                spec_refs=["ТЗ 4.5.5", "ТС 4.6.7"],
            ))
    # Права доступа к журналу и ключу
    acl_calls: list[tuple[str, int, str, str]] = []
    for rel in p.py_files():
        for i, line in enumerate(p.lines(rel), start=1):
            m = ACL_CALL_RE.search(line)
            if m and not line.lstrip().startswith("def "):
                acl_calls.append((rel, i, m.group(1), m.group(2)))
    log_key_expr = str((p.setting("LOG_KEY_FILE") or {}).get("value", ""))
    if acl_calls:
        out.note_checked("IB-05", f"настройка прав доступа к рабочему каталогу: {len(acl_calls)} вызовов set_reader_access")
    for rel, line, expr, access in acl_calls:
        e = expr.lower()
        if "pending" in e and access == "modify":
            out.add(RuleFinding(
                requirement_id="IB-05", rule_id="ib05.pending_journal_writable_by_local_user",
                file=rel, line=line, function="configure",
                justification=(f"Каталог неотправленных записей журнала ({expr}) получает право modify для непривилегированных локальных субъектов: "
                               f"записи могут быть удалены или подменены до передачи сборщику событий (ТС 4.6.7 требует защиты от подмены и удаления)."),
                severity="high",
                recommendation="Выдавать на каталог pending только права владельца процесса и SYSTEM; непривилегированным субъектам — none.",
                spec_refs=["ТЗ 4.5.5", "ТС 4.6.7"],
            ))
        elif "journal" in e and "pending" not in e and "received" not in e and access in ("read", "modify") and ("journal" in log_key_expr.lower() or "journal.key" in p.text(rel)):
            out.add(RuleFinding(
                requirement_id="IB-05", rule_id="ib05.journal_key_readable_by_local_user",
                file=rel, line=line, function="configure",
                justification=(f"Каталог журнала ({expr}), в котором хранится ключ шифрования журнала (LOG_KEY_FILE = {log_key_expr}), "
                               f"доступен на чтение непривилегированным локальным субъектам: зная ключ, пользователь может расшифровать, "
                               f"подделать и заново зашифровать записи — шифрование не защищает журнал от модификации."),
                severity="high",
                recommendation="Хранить journal.key в каталоге keys (доступ none) отдельно от записей журнала либо закрыть чтение каталога journal.",
                spec_refs=["ТЗ 4.5.5", "ТС 4.5.4", "ТС 4.6.7"],
            ))
        elif ("key" in e) and access != "none":
            out.add(RuleFinding(
                requirement_id="IB-05", rule_id="ib05.key_store_readable",
                file=rel, line=line, function="configure",
                justification=f"Каталог ключей ({expr}) доступен непривилегированным субъектам ({access}).",
                severity="high",
                recommendation="Установить доступ none для непривилегированных субъектов.",
                spec_refs=["ТЗ 4.5.5", "ТС 4.5.4"],
            ))
        elif "received" in e and access != "none":
            out.add(RuleFinding(
                requirement_id="IB-05", rule_id="ib05.received_store_accessible",
                file=rel, line=line, function="configure",
                justification=f"Хранилище принятых записей ({expr}) доступно непривилегированным субъектам ({access}).",
                severity="medium",
                recommendation="Закрыть доступ (none) к хранилищу принятых записей.",
                spec_refs=["ТЗ 4.5.5", "ТС 4.6.7"],
            ))
    if writers and not acl_calls and not any(re.search(r"os\.chmod\(|icacls|SetNamedSecurityInfo|chmod ", p.text(r)) for r in p.py_files()):
        rel, line, _ = writers[0]
        out.add(RuleFinding(
            requirement_id="IB-05", rule_id="ib05.no_filesystem_protection",
            file=rel, line=line, function=None, confidence="likely",
            justification="В проекте не найдено средств ограничения прав доступа к файлам журнала (chmod/ACL): локальный пользователь может изменить или удалить записи до их отправки.",
            severity="medium",
            recommendation="При первоначальной настройке выставлять права на каталог журнала только для учётной записи службы.",
            spec_refs=["ТЗ 4.5.5", "ТС 4.6.7"],
        ))
    # Диагностический журнал Django в открытом виде
    logging_cfg = p.setting_value("LOGGING")
    if isinstance(logging_cfg, dict):
        for hname, h in (logging_cfg.get("handlers") or {}).items():
            cls = str((h or {}).get("class", ""))
            if re.search(r"FileHandler", cls):
                out.add(RuleFinding(
                    requirement_id="IB-05", rule_id="ib05.plaintext_file_logging",
                    file=p.settings_file() or "settings.py", line=p.setting_line("LOGGING"), function=f"LOGGING.handlers.{hname}",
                    justification=f"Обработчик журнала `{hname}` ({cls}) пишет диагностический журнал в файл открытым текстом.",
                    severity="high",
                    recommendation="Отключить файловый обработчик или направить записи через шифрующий обработчик.",
                    spec_refs=["ТЗ 4.5.5", "ТС 4.5.6", "ТС 4.11.5"],
                ))
    # Сборщик: изоляция повреждённых записей (ТС 4.6.7) — не блокирует
    for rel in p.py_files():
        if "collector" not in Path(rel).name.lower():
            continue
        text = p.text(rel)
        if re.search(r"for .+ in .+glob\(", text) and "try:" not in text:
            line = p.find_line(rel, r"for .+ in .+glob\(") or 1
            out.additional.append({
                "category": "audit-detail", "severity": "medium",
                "description": "Сборщик событий не изолирует повреждённые записи: исключение при расшифровке одной записи прерывает обработку остальных (ТС 4.6.7 требует изоляции повреждённых записей без остановки обработки).",
                "location": {"file": rel, "line": line, "function": "collect_once"},
                "spec_refs": ["ТС 4.6.7"],
            })


# ---------------------------------------------------------------------------
# ИБ-06. Ссылки на нормативную базу в документации (детерминированно)
# ---------------------------------------------------------------------------

def check_ib06(p: Project, out: RuleOutcome):
    from requirements_ru import REGULATORY_ACTS_RU
    rr = p.index.get("regulatory_references", {}) or {}
    searched = rr.get("searched_files", [])
    if searched:
        out.note_checked("IB-06", f"README/текстовые документы: {', '.join(searched)}")
    readme = next((f for f in searched if f.lower().startswith("readme")), None)
    for key, found in (rr.get("reference_found") or {}).items():
        if found:
            continue
        anchor_file = readme or (searched[0] if searched else "README.md")
        anchor_line = None
        if anchor_file and p.exists(anchor_file):
            anchor_line = p.find_line(anchor_file, r"(?i)нормативн|стандарт|закон|источник") or 1
        out.add(RuleFinding(
            requirement_id="IB-06", rule_id="ib06.reference_missing_in_readme",
            file=anchor_file, line=anchor_line, function=None,
            justification=f"В документации ({', '.join(searched) or 'README не найден'}) отсутствует ссылка на «{REGULATORY_ACTS_RU.get(key, key)}».",
            severity="medium",
            recommendation=f"Добавить в раздел нормативных источников README наименование и ссылку: {REGULATORY_ACTS_RU.get(key, key)}.",
            spec_refs=["ТЗ 4.5.6", "ТЗ 3.1", "ТС 4.10.2"],
        ))
    for rel, d in (rr.get("docx") or {}).items():
        out.note_checked("IB-06", f"{rel}: {d.get('paragraphs_total')} абзацев, гиперссылок: {len(d.get('hyperlinks') or [])}")
        is_spec = re.search(r"спецификац|техническ|ТЗ|тз", Path(rel).name, re.I) is not None
        for key, found in (d.get("reference_found") or {}).items():
            if found or not is_spec:
                continue
            out.add(RuleFinding(
                requirement_id="IB-06", rule_id="ib06.reference_missing_in_spec_docx",
                file=rel, line=1, function=None,
                justification=f"В техническом документе {rel} отсутствует упоминание «{REGULATORY_ACTS_RU.get(key, key)}» (ТС 4.10.2 требует наименования и ссылки в технической спецификации).",
                severity="medium",
                recommendation=f"Добавить в раздел нормативной основы документа: {REGULATORY_ACTS_RU.get(key, key)}.",
                spec_refs=["ТЗ 4.5.6", "ТС 4.10.2"],
            ))
    if not searched and not rr.get("docx"):
        out.limitations.append("ИБ-06: документация (README.md, docs/) не найдена.")


# ---------------------------------------------------------------------------
# ИБ-07. Единый журнал действий пользователей и событий СУБД
# ---------------------------------------------------------------------------

READ_VIEW_RE = re.compile(r"list|detail|view|show|attachment|download|api|catalog|search|feed|index|home|dashboard|report", re.I)
MUTATING_VIEW_RE = re.compile(r"delete|remove|update|create|new|bulk|token|issue|login|logout|password|role|grant|revoke|manage", re.I)
DB_EVENT_RE = re.compile(r"connection_created|set_trace_callback|pre_migrate|post_migrate|execute_wrapper|DatabaseWrapper|sqlite_trace|db_events|schema_editor|trace_callback")


def _audit_record_names(p: Project) -> set[str]:
    names: set[str] = set()
    for r in p.index.get("routes", []):
        for a in r.get("audit_calls") or []:
            names.add(a["name"])
    for rel in p.py_files():
        if re.search(r"audit|journal", Path(rel).name, re.I):
            tree = p.tree(rel)
            if tree:
                for node in tree.body:
                    if isinstance(node, ast.FunctionDef) and node.name in ("record", "log_event", "audit", "write_event", "emit"):
                        dotted = rel[:-3].replace("/", ".") if rel.endswith(".py") else rel
                        names.add(f"{dotted}.{node.name}")
    return names


def check_ib07(p: Project, out: RuleOutcome):
    routes = p.index.get("routes", [])
    wiring = p.index.get("signal_wiring", {}) or {}
    conns = wiring.get("connections", []) or []
    signals = {_short(c.get("signal", "")) for c in conns}
    audit_names = _audit_record_names(p)
    audit_file = None
    audit_line = None
    for n in sorted(audit_names):
        mod, fn = n.rsplit(".", 1)
        rel = p.module_file(mod)
        if rel:
            fs = p.function_source(rel, fn)
            if fs:
                audit_file, audit_line = rel, fs[0]
                break
    # middleware-уровень журналирования?
    middleware = p.setting_value("MIDDLEWARE") or []
    mw_logs = False
    mw_file, mw_line = None, None
    for mw in middleware:
        if not isinstance(mw, str):
            continue
        rel = p.module_file(mw.rsplit(".", 1)[0])
        if rel:
            if mw_file is None:
                mw_file, mw_line = rel, 1
            txt = p.text(rel)
            if re.search(r"\brecord\(|(audit|journal|log)\w*\.(record|write|emit|log|event|create|save|append)\(|log_event\(", txt):
                mw_logs = True
            if mw_line == 1:
                mw_line = p.find_line(rel, r"^class\s+\w*Middleware") or 1
    out.note_checked("IB-07", f"сигналы аудита: {sorted(signals) or 'нет'}; функции записи журнала: {sorted(audit_names) or 'нет'}; журналирующий middleware: {'да' if mw_logs else 'нет'}")

    if not conns and not mw_logs and not audit_names:
        sfile = p.settings_file()
        out.add(RuleFinding(
            requirement_id="IB-07", rule_id="ib07.no_central_audit_mechanism",
            file=sfile or "settings.py", line=p.setting_line("MIDDLEWARE") or 1, function="MIDDLEWARE",
            justification="Единый механизм журналирования действий пользователей (сигналы ORM, middleware или общий компонент аудита) в проекте не обнаружен.",
            severity="critical",
            recommendation="Реализовать общий компонент аудита (middleware + сигналы), охватывающий веб-интерфейс, API, выгрузки и пакетные операции.",
            spec_refs=["ТЗ 4.5.7", "ТС 4.6.1", "ТС 4.6.2"],
        ))
        return

    # Полнота сигналов
    expected = {"post_save": "создание/изменение объектов", "post_delete": "удаление объектов",
                "user_logged_in": "успешный вход", "user_logged_out": "выход", "user_login_failed": "отказ входа"}
    missing = [f"{s} ({why})" for s, why in expected.items() if s not in signals]
    if missing and conns and not mw_logs:
        c0 = conns[0]
        out.add(RuleFinding(
            requirement_id="IB-07", rule_id="ib07.audit_signals_incomplete",
            file=c0["file"], line=c0["line"], function="ready",
            justification=f"К механизму аудита не подключены сигналы: {', '.join(missing)} — соответствующие события не попадают в журнал (ТС 4.6.4).",
            severity="high",
            recommendation="Подключить недостающие сигналы к общему обработчику аудита.",
            spec_refs=["ТЗ 4.5.7", "ТС 4.6.4"],
        ))
    # Непокрытые модели
    uncovered = [m for m in p.index.get("model_audit_coverage", []) if not m.get("covered_by_post_save_post_delete_signals")]
    if uncovered and conns:
        filt = next(iter((wiring.get("handler_app_label_filters") or {}).values()), {})
        out.add(RuleFinding(
            requirement_id="IB-07", rule_id="ib07.models_not_covered_by_audit",
            file=filt.get("file") or conns[0]["file"], line=filt.get("line") or conns[0]["line"], function=None,
            justification="Обработчик аудита ограничен фильтром app_label и не охватывает модели: " + ", ".join(f"{m['app_label']}.{m['class_name']}" for m in uncovered) + ".",
            severity="high",
            recommendation="Снять фильтр app_label или включить в него все приложения с данными.",
            spec_refs=["ТЗ 4.5.7", "ТС 4.6.2"],
        ))
    # Чтение/просмотр не журналируется
    if not mw_logs and routes:
        unlogged = []
        for r in routes:
            blob = f"{r.get('pattern','')} {r.get('view_function','') or ''}"
            if not r.get("view_file") or PUBLIC_ROUTE_RE.search(r.get("pattern", "") or ""):
                continue
            if EXPORT_RE.search(blob):
                continue  # выгрузки — предмет ИБ-08
            if not READ_VIEW_RE.search(blob):
                continue
            if MUTATING_VIEW_RE.search(blob) or any(_short(n) == "require_POST" for n in (r.get("decorators") or []) + (r.get("url_level_wrappers") or [])):
                continue   # изменяющие операции покрываются сигналами ORM
            if r.get("audit_calls"):
                continue
            unlogged.append(r)
        unlogged = _dedupe_routes(unlogged)
        if unlogged:
            anchor_file = audit_file or mw_file or unlogged[0]["view_file"]
            anchor_line = audit_line or mw_line or unlogged[0]["view_line"]
            out.add(RuleFinding(
                requirement_id="IB-07", rule_id="ib07.read_access_not_logged",
                file=anchor_file, line=anchor_line, function=("record" if anchor_file == audit_file else None), confidence="likely",
                justification=(f"Журналирование реализовано только через сигналы изменения данных и события входа: операции чтения — "
                               f"просмотр списков и карточек обращений, скачивание вложений, чтение через API — не регистрируются ни middleware, "
                               f"ни в представлениях. Незарегистрированные маршруты чтения ({len(unlogged)}): "
                               + ", ".join(f"{r.get('pattern')} → {r.get('view_function')} ({r.get('view_file')}:{r.get('view_line')})" for r in unlogged)
                               + ". Журнал не охватывает проект в целом (ТС 4.6.1, 4.6.4: просмотр списков, карточек, скачивание вложений, чтение через API подлежат регистрации)."),
                severity="high",
                recommendation="Регистрировать операции чтения общим компонентом (middleware на каждый запрос к защищённым маршрутам с типом операции, объектом и результатом) вместо точечных вызовов в отдельных функциях.",
                related_locations=[{"file": r["view_file"], "line": r.get("view_line"), "function": r.get("view_function"), "pattern": r.get("pattern")} for r in unlogged],
                spec_refs=["ТЗ 4.5.7", "ТС 4.6.1", "ТС 4.6.2", "ТС 4.6.4"],
            ))
    # Обход сигналов пакетными операциями
    for h in p.index.get("bulk_orm_calls", []) or []:
        if not h.get("looks_like_queryset"):
            continue
        rel = h["file"]
        in_views = bool(re.search(r"views|api|serializers|update_ticket", rel)) and "/helpdesk/" not in rel
        enclosing = ""
        tree = p.tree(rel)
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= h["line"] <= (getattr(node, "end_lineno", node.lineno) or node.lineno):
                    enclosing = ast.get_source_segment(p.text(rel), node) or ""
        if enclosing and re.search(r"\brecord\(|audit\.record\(", enclosing):
            continue  # пакетная операция регистрируется явно
        if in_views:
            out.add(RuleFinding(
                requirement_id="IB-07", rule_id="ib07.bulk_update_bypasses_audit",
                file=rel, line=h["line"], function=None,
                justification=(f"Пакетное изменение данных `{h.get('call_source')}` выполняется через QuerySet.{h.get('method')}(): сигналы post_save не срабатывают, "
                               f"механизм аудита это изменение не регистрирует. ТС 4.6.4 требует регистрировать пакетную смену статусов с указанием затронутых обращений."),
                severity="high",
                recommendation="Регистрировать пакетную операцию явно (audit.record с перечнем идентификаторов) либо выполнять изменения через save() каждого объекта.",
                spec_refs=["ТЗ 4.5.7", "ТС 4.6.4", "ТС 4.6.6"],
            ))
        elif "/helpdesk/" not in rel:
            out.additional.append({
                "category": "audit-detail", "severity": "low",
                "description": f"Изменение данных в обход сигналов аудита: `{h.get('call_source')}` (QuerySet.{h.get('method')}()) — событие не регистрируется.",
                "location": {"file": rel, "line": h["line"]},
                "spec_refs": ["ТС 4.6.6"],
            })
    # Журнал событий СУБД
    db_hits = [rel for rel in p.py_files() if DB_EVENT_RE.search(p.text(rel))]
    logging_cfg = p.setting_value("LOGGING")
    db_logger = False
    if isinstance(logging_cfg, dict):
        for lname, lcfg in (logging_cfg.get("loggers") or {}).items():
            if lname.startswith("django.db") and (lcfg or {}).get("handlers") and "null" not in str((lcfg or {}).get("handlers")):
                db_logger = True
    out.note_checked("IB-07", f"признаки журнала событий СУБД: {db_hits or 'не найдены'}; логгер django.db с обработчиком: {'да' if db_logger else 'нет'}")
    if not db_hits and not db_logger and p.settings_file():
        out.add(RuleFinding(
            requirement_id="IB-07", rule_id="ib07.no_dbms_event_log",
            file=p.settings_file(), line=p.setting_line("DATABASES") or 1, function="DATABASES", confidence="likely",
            justification=("Журнал событий СУБД не реализован: нет обработчиков сигнала connection_created, трассировки SQLite (set_trace_callback), "
                           "регистрации миграций (pre/post_migrate) или изменения прав на файл БД; логгер django.db не имеет обработчика. "
                           "ТЗ ИБ-07 и ТС 4.6.5 требуют вести журнал событий СУБД (соединения, отказы, изменение структуры, права на файл БД)."),
            severity="high",
            recommendation="Подключить connection_created для регистрации соединений, регистрировать миграции и команду db_access через общий аудит, включить трассировку DDL.",
            spec_refs=["ТЗ 4.5.7", "ТС 4.6.5"],
        ))
    # Отказы в доступе
    denial_logged = False
    for rel in p.py_files():
        text = p.text(rel)
        if re.search(r"PermissionDenied|handler403|status=403|process_exception", text) and re.search(r"\brecord\(|audit\.record|log_event\(", text):
            tree = p.tree(rel)
            if tree:
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        seg = ast.get_source_segment(text, node) or ""
                        if re.search(r"PermissionDenied|403|process_exception", seg) and re.search(r"\brecord\(|audit\.record", seg) and not re.search(r"raise PermissionDenied", seg):
                            denial_logged = True
    if not denial_logged and (audit_file or mw_file):
        out.add(RuleFinding(
            requirement_id="IB-07", rule_id="ib07.access_denials_not_logged",
            file=mw_file or audit_file, line=mw_line or audit_line, function=None, confidence="likely",
            justification="Отказы в доступе к защищённым операциям (PermissionDenied/403) нигде не регистрируются в журнале аудита: нет обработчика исключений или middleware, записывающего событие отказа (ТС 4.6.4).",
            severity="medium",
            recommendation="В middleware (process_exception) или обработчике 403 записывать событие отказа с идентификатором пользователя, объектом и маршрутом.",
            spec_refs=["ТЗ 4.5.7", "ТС 4.6.4"],
        ))


# ---------------------------------------------------------------------------
# ИБ-08. Контроль выгрузки персональных данных
# ---------------------------------------------------------------------------

PII_IN_CODE_RE = re.compile(r"email|last_name|first_name|middle_name|username|phone|'login'|\"login\"")


def check_ib08(p: Project, out: RuleOutcome, resolver: GuardResolver):
    routes = p.index.get("routes", [])
    export_routes = []
    for r in routes:
        blob = f"{r.get('pattern','')} {r.get('name','') or ''} {r.get('view_function','') or ''}"
        if EXPORT_RE.search(blob) and r.get("view_file"):
            export_routes.append(r)
    out.note_checked("IB-08", f"маршрутов выгрузки/скачивания данных: {len(export_routes)} ({', '.join(r.get('pattern','') for r in export_routes) or '—'})")
    for r in export_routes:
        cls = resolver.classify(r)
        src = cls["view_source"]
        # ПД в самой функции или в вызываемом помощнике того же модуля
        has_pii = bool(PII_IN_CODE_RE.search(src))
        helper_used = None
        if not has_pii:
            for call_name in set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", src)):
                fs = p.function_source(r["view_file"], call_name)
                if fs and PII_IN_CODE_RE.search(fs[1]):
                    has_pii, helper_used = True, call_name
                    break
        if not has_pii:
            continue
        audited = bool(r.get("audit_calls"))
        if not audited:
            for call_name in set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", src)):
                fs = p.function_source(r["view_file"], call_name)
                if fs and re.search(r"audit\.record\(|\brecord\(", fs[1]):
                    audited = True
                    break
        problems = []
        if cls["level"] != "admin_role":
            level_txt = {"none": "без аутентификации", "authenticated": "любому аутентифицированному пользователю (только login_required)",
                         "weak_flag": f"по техническому признаку is_staff/is_superuser ({_short(cls['weak_by'] or '')})"}[cls["level"]]
            problems.append(f"роль «администратор» на сервере не проверяется — выгрузка доступна {level_txt}")
        if not audited:
            problems.append("факт выгрузки не фиксируется в журнале аудита (нет вызова audit.record / аналогичного)")
        if not problems:
            continue
        sev = "critical" if cls["level"] in ("none", "authenticated") else "high"
        out.add(RuleFinding(
            requirement_id="IB-08", rule_id="ib08.pii_export_without_role_check_or_audit",
            file=r["view_file"], line=r.get("view_line"), function=r.get("view_function"),
            justification=(f"Маршрут `{r.get('pattern')}` ({r.get('view_function')}) выгружает персональные данные пользователей "
                           f"({'через ' + helper_used + '()' if helper_used else 'логин, ФИО, e-mail, роль'}): " + "; ".join(problems) + ". "
                           f"Декораторы: {_decorators_text(r)}."),
            severity=sev,
            recommendation="Защитить выгрузку тем же серверным декоратором роли администратора, что и остальные форматы выгрузки, и записывать событие выгрузки в аудит с датой, инициатором, форматом и числом записей.",
            spec_refs=["ТЗ 4.5.8", "ТС 4.7.2", "ТС 4.7.3"],
        ))


# ---------------------------------------------------------------------------
# Несоответствия технической спецификации (не блокируют пайплайн, ТЗ 4.8.1)
# ---------------------------------------------------------------------------

def _project_functions(p: Project, include_library: bool = False):
    """(rel, lineno, name, source) для всех функций проекта (кроме библиотечного src/, если не указано)."""
    for rel in p.py_files():
        if not include_library and rel.startswith("src/"):
            continue
        if "/management/commands/" in rel or "/migrations/" in rel:
            continue
        tree = p.tree(rel)
        if tree is None:
            continue
        text = p.text(rel)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield rel, node.lineno, node.name, ast.get_source_segment(text, node) or ""


def check_spec_gaps(p: Project, out: RuleOutcome):
    add = out.additional.append
    for rel, line, name, src in _project_functions(p):
        # ТС 4.3.5: право на очередь — только роли «оператор»
        if re.search(r"user_permissions\.add\(|groups\.add\(", src) and not re.search(r"role\s*(==|!=|in|not in)", src):
            add({"category": "access-control-detail", "severity": "medium",
                 "description": f"`{name}` выдаёт право на очередь (user_permissions.add) без проверки, что получатель имеет роль «оператор» (ТС 4.3.5: право на очередь выдаётся только учётным записям с ролью «оператор»).",
                 "location": {"file": rel, "line": line, "function": name}, "spec_refs": ["ТС 4.3.5"]})
        # ТС 4.3.5: при смене роли права на очереди снимаются
        if re.search(r"\.role\s*=\s*(?!=)", src) and "form" not in name.lower() and not re.search(r"user_permissions\.(clear|set|remove)\(|groups\.(clear|set)\(", src):
            add({"category": "access-control-detail", "severity": "medium",
                 "description": f"`{name}` изменяет роль пользователя, но не снимает ранее выданные права на очереди (user_permissions не очищаются) — бывший оператор, переведённый в заявители, сохраняет права (ТС 4.3.5).",
                 "location": {"file": rel, "line": line, "function": name}, "spec_refs": ["ТС 4.3.5"]})
        # ТС 4.3.2: членство в группах не должно расширять область оператора
        if "get_all_permissions()" in src:
            ln = line + src.split("\n").index(next(x for x in src.split("\n") if "get_all_permissions()" in x))
            add({"category": "access-control-detail", "severity": "low",
                 "description": f"`{name}` определяет доступные оператору очереди через get_all_permissions(), которое включает права групп: членство в группе расширяет область доступа оператора, что запрещено ТС 4.3.2 (права на очереди выдаются явно).",
                 "location": {"file": rel, "line": ln, "function": name}, "spec_refs": ["ТС 4.3.2"]})
        # ТС 4.11.2: проверка содержимого вложения, а не только расширения
        if name.startswith("clean_") and re.search(r"suffix|splitext|endswith\(", src) and re.search(r"\.size|size\s*>", src) \
                and not re.search(r"magic|imghdr|PIL|Image\.open|%PDF|\\x89PNG|read\(|startswith\(b|subprocess|filetype|mimetypes\.guess", src):
            add({"category": "data-handling-detail", "severity": "medium",
                 "description": f"`{name}` проверяет вложение только по расширению и размеру; соответствие содержимого заявленному формату и отсутствие активного содержимого не проверяются (ТС 4.11.2 требует проверку содержимого в изолированном процессе).",
                 "location": {"file": rel, "line": line, "function": name}, "spec_refs": ["ТС 4.11.2"]})
        # ТС 4.7.4: защита CSV от формул — неполный набор префиксов
        m = re.search(r"startswith\(\(\s*(['\"][=+\-@]['\"]\s*,\s*)+['\"][=+\-@]['\"]\s*\)\)", src)
        if m and "csv" in src.lower() and not re.search(r"\\t|\\r", m.group(0)):
            ln = line + src[:m.start()].count("\n")
            add({"category": "export-detail", "severity": "low",
                 "description": f"`{name}`: экранирование формул в CSV не учитывает префиксы табуляции и возврата каретки (\\t, \\r), которые табличные редакторы также интерпретируют (ТС 4.7.4).",
                 "location": {"file": rel, "line": ln, "function": name}, "spec_refs": ["ТС 4.7.4"]})
    # ТС 4.6.3 / 4.6.6: состав записи аудита и согласованность с транзакцией
    audit_rel = (p.index.get("log_protection") or {}).get("audit_module")
    if audit_rel:
        fs = p.function_source(audit_rel, "record")
        if fs:
            line, src = fs
            missing = [label for label, rx in (("результат операции", r"result|outcome|status"),
                                               ("идентификатор запроса", r"request_id|req_id|correlation"),
                                               ("идентификатор источника запроса", r"source|remote_addr|client_ip|REMOTE_ADDR|ip_hash"))
                       if not re.search(rx, src)]
            if missing:
                add({"category": "audit-detail", "severity": "medium",
                     "description": f"Запись журнала аудита (`record`) не содержит обязательных по ТС 4.6.3 полей: {', '.join(missing)}.",
                     "location": {"file": audit_rel, "line": line, "function": "record"}, "spec_refs": ["ТС 4.6.3"]})
        if "on_commit" not in p.text(audit_rel):
            anchor = p.find_line(audit_rel, r"^def mutation|^def deletion") or 1
            add({"category": "audit-detail", "severity": "medium",
                 "description": "События изменения данных пишутся в журнал непосредственно из сигналов post_save/post_delete, без transaction.on_commit: при откате транзакции в журнале остаётся событие успешной операции (ТС 4.6.6).",
                 "location": {"file": audit_rel, "line": anchor, "function": "mutation"}, "spec_refs": ["ТС 4.6.6"]})
    # ТС 4.9.3: статика неподключённых библиотечных компонентов не обслуживается
    middleware = p.setting_value("MIDDLEWARE") or []
    apps = p.setting_value("INSTALLED_APPS") or []
    if any(isinstance(m, str) and "whitenoise" in m.lower() for m in middleware):
        routed = {str(r.get("view_module") or "").split(".")[0] for r in p.index.get("routes", [])}
        for app in apps:
            if not isinstance(app, str) or app.startswith(("django.", "rest_framework", "whitenoise")):
                continue
            top = app.split(".")[0]
            if top in routed:
                continue
            static_dir = next((b / top / "static" for b in p.search_roots if (b / top / "static").is_dir()), None)
            if static_dir is not None:
                add({"category": "transport-detail", "severity": "low",
                     "description": f"Приложение `{top}` включено в INSTALLED_APPS, но его маршруты не подключены к ROOT_URLCONF; при этом WhiteNoise раздаёт статику всех приложений (collectstatic), включая `{p.rel(static_dir)}` — статические ресурсы неподключённых библиотечных компонентов не должны обслуживаться (ТС 4.9.3).",
                     "location": {"file": p.settings_file() or "settings.py", "line": p.setting_line("INSTALLED_APPS") or 1, "function": "INSTALLED_APPS"},
                     "spec_refs": ["ТС 4.9.3", "ТС 4.1.5"]})


# ---------------------------------------------------------------------------
# Оркестрация
# ---------------------------------------------------------------------------

def run_rules(index: dict, project_root: Path) -> RuleOutcome:
    p = Project(Path(project_root), index)
    out = RuleOutcome()
    resolver = GuardResolver(p)
    steps = [
        ("IB-01", lambda: check_ib01(p, out, resolver)),
        ("IB-02", lambda: check_ib02(p, out, resolver)),
        ("IB-03", lambda: check_ib03(p, out)),
        ("IB-04", lambda: check_ib04(p, out)),
        ("IB-05", lambda: check_ib05(p, out)),
        ("IB-06", lambda: check_ib06(p, out)),
        ("IB-07", lambda: check_ib07(p, out)),
        ("IB-08", lambda: check_ib08(p, out, resolver)),
        ("ТС", lambda: check_spec_gaps(p, out)),
    ]
    for rid, fn in steps:
        try:
            fn()
        except Exception as exc:  # правило не должно ронять проверку
            out.limitations.append(f"{rid}: правило завершилось ошибкой ({type(exc).__name__}: {exc}); требование оценивается только моделью.")
    # сверка: строка должна существовать в файле
    kept: list[RuleFinding] = []
    for f in out.findings:
        lines = p.lines(f.file) if f.file else []
        if not f.file or not lines:
            out.limitations.append(f"{f.requirement_id}/{f.rule_id}: файл {f.file!r} не читается — находка отброшена.")
            continue
        if f.line is None or not (1 <= f.line <= len(lines)):
            f.line = 1
        kept.append(f)
    # дедупликация по (требование, файл, строка)
    seen: set[tuple] = set()
    unique: list[RuleFinding] = []
    for f in kept:
        key = (f.requirement_id, f.file, f.line, f.rule_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    out.findings = unique
    seen_add: set[tuple] = set()
    uniq_add = []
    for a in out.additional:
        loc = a.get("location") or {}
        key = (a.get("category"), loc.get("file"), loc.get("line"))
        if key in seen_add:
            continue
        seen_add.add(key)
        uniq_add.append(a)
    out.additional = uniq_add
    return out
