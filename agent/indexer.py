"""Deterministic, static project indexer (IB-check agent, module 2).

Builds a structural map of a Django project WITHOUT executing it:
  - URL routes, resolved through include()/path() chains, with every
    decorator/wrapper applied at the urls.py callsite AND on the view
    function itself, plus any in-body guard calls (e.g. a call like
    `access.operator_required(request.user)` as the first statement of
    a view, which is a real guard pattern in this codebase but is not a
    decorator and would be invisible to decorator-only detection).
  - Every model in every locally-defined app, with a PII-name heuristic
    on its fields.
  - Every top-level assignment in the Django settings module (config
    flags), literal-evaluated where possible.

Design choice, not an oversight: this does NOT import/execute the
target's settings.py or call django.setup(). Rationale: the agent must
run unmodified against both the "reference" and "violated" copies of
the test project (docs/01-task-overview.md), and this repo's own
settings.py reads a secret-key file from `runtime/keys/` that does not
exist on a fresh checkout (demodesk/config/settings.py:5) - executing
it would crash before any check ran. Static AST analysis has no such
dependency and never executes target code, which also matters if the
"violated" copy is not a valid, importable Django project.

This module is intentionally conservative: anything it cannot resolve
statically is recorded in `notes` rather than silently dropped or
guessed at, per docs/05's "explicit checked vs insufficient data"
philosophy carried down from the report schema into the indexer itself.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

PII_NAME_HINTS = (
    "email", "e_mail", "mail", "name", "fio", "fam", "login", "username",
    "phone", "tel", "address", "adres", "birth", "passport", "iin", "snils",
    "password", "submitter",
)
GUARD_NAME_HINTS = (
    "required", "permission", "administrator", "operator", "is_staff",
    "role", "allowed", "forbidden", "denied",
)
SKIP_APP_PREFIXES = (
    "django.", "rest_framework", "whitenoise", "corsheaders",
)
EXCLUDE_DIR_PARTS = {
    "migrations", "licenses", ".venv", "venv", "node_modules",
    "agent", "__pycache__", ".git", "runtime",
}


def literal_or_source(node: ast.AST):
    """Try ast.literal_eval; fall back to unparsed source, never raise."""
    try:
        return ast.literal_eval(node), True
    except Exception:
        try:
            return ast.unparse(node), False
        except Exception:
            return "<unparseable>", False


@dataclass
class Note:
    where: str
    message: str


class Indexer:
    def __init__(self, root: Path):
        self.root = root
        self.search_roots = [root]
        self.notes: list[Note] = []
        self._module_cache: dict[str, ast.Module] = {}
        self._module_path_cache: dict[str, Path | None] = {}

    def note(self, where: str, message: str):
        self.notes.append(Note(where, message))

    # ---------- module resolution ----------

    def module_to_file(self, dotted: str) -> Path | None:
        if dotted in self._module_path_cache:
            return self._module_path_cache[dotted]
        parts = dotted.split(".")
        result = None
        for base in self.search_roots:
            candidate = base.joinpath(*parts)
            as_module = candidate.with_suffix(".py")
            as_package = candidate / "__init__.py"
            if as_module.is_file():
                result = as_module
                break
            if as_package.is_file():
                result = as_package
                break
        self._module_path_cache[dotted] = result
        return result

    def path_to_dotted(self, path: Path) -> str | None:
        for base in self.search_roots:
            try:
                rel = path.relative_to(base)
            except ValueError:
                continue
            parts = list(rel.parts)
            if parts[-1] == "__init__.py":
                parts = parts[:-1]
            elif parts[-1].endswith(".py"):
                parts[-1] = parts[-1][:-3]
            return ".".join(parts)
        return None

    def parse_module(self, dotted: str) -> tuple[ast.Module, Path] | None:
        path = self.module_to_file(dotted)
        if path is None:
            return None
        if dotted not in self._module_cache:
            try:
                src = path.read_text(encoding="utf-8")
                self._module_cache[dotted] = ast.parse(src, filename=str(path))
            except Exception as exc:  # pragma: no cover - defensive
                self.note(dotted, f"failed to parse {path}: {exc}")
                return None
        return self._module_cache[dotted], path

    # ---------- import maps ----------

    def build_import_map(self, tree: ast.Module, current_module: str | None = None) -> dict[str, str]:
        """name-in-this-module -> best-effort dotted target.

        `current_module` (this module's own dotted path, e.g. 'portal.apps')
        is required to resolve relative imports (`from . import audit`,
        `from .foo import bar`) correctly - without it, `from . import x`
        (node.module is None) was silently dropped entirely, which broke
        resolution of e.g. `from . import audit` in portal/apps.py.
        """
        imports: dict[str, str] = {}
        current_parts = current_module.split(".") if current_module else []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imports[local] = alias.name
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    if not current_parts:
                        self.note("import-resolve", f"relative import at line {node.lineno} but current module dotted path unknown; skipped")
                        continue
                    # package containing this module, then go up (level-1) more
                    package_parts = current_parts[:-1]
                    if node.level > 1:
                        package_parts = package_parts[: len(package_parts) - (node.level - 1)]
                    base = ".".join(package_parts + ([node.module] if node.module else []))
                elif node.module:
                    base = node.module
                else:
                    continue
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports[local] = f"{base}.{alias.name}" if base else alias.name
        return imports

    def resolve_name_chain(self, node: ast.AST, import_map: dict[str, str]) -> str:
        """Best-effort dotted-string for a Name/Attribute chain."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        parts.reverse()
        if not parts:
            try:
                return ast.unparse(node)
            except Exception:
                return "<?>"
        head, rest = parts[0], parts[1:]
        resolved_head = import_map.get(head, head)
        return ".".join([resolved_head, *rest]) if rest else resolved_head

    # ---------- settings ----------

    def find_settings_module(self) -> str | None:
        manage = self.root / "manage.py"
        if not manage.is_file():
            self.note("manage.py", "not found at project root")
            return None
        tree = ast.parse(manage.read_text(encoding="utf-8"), filename=str(manage))
        settings_module = None
        for node in ast.walk(tree):
            # sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "insert" and self.resolve_name_chain(node.func.value, {}).endswith("path"):
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            candidate = self.root / sub.value
                            if candidate.is_dir():
                                self.search_roots.append(candidate)
            # os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'x.y.z')
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "setdefault":
                args = node.args
                if len(args) == 2 and isinstance(args[0], ast.Constant) and args[0].value == "DJANGO_SETTINGS_MODULE":
                    if isinstance(args[1], ast.Constant):
                        settings_module = args[1].value
        if settings_module is None:
            self.note("manage.py", "DJANGO_SETTINGS_MODULE not found statically")
        return settings_module

    def index_settings(self, dotted: str) -> dict:
        out: dict[str, dict] = {}
        parsed = self.parse_module(dotted)
        if parsed is None:
            self.note("settings", f"could not locate/parse settings module {dotted}")
            return out
        tree, path = parsed
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                value, resolved = literal_or_source(node.value)
                out[name] = {"value": value, "resolved": resolved, "line": node.lineno}
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name = node.target.id
                if node.value is not None:
                    value, resolved = literal_or_source(node.value)
                    out[name] = {"value": value, "resolved": resolved, "line": node.lineno}
        return out

    # ---------- urls ----------

    def unwrap_view(self, expr: ast.AST, import_map: dict[str, str]):
        """Peel decorator-at-callsite wrappers off a urls.py view expression.

        Returns (target_dotted, is_cbv, wrappers: list[str]).
        """
        wrappers: list[str] = []
        cur = expr
        while isinstance(cur, ast.Call):
            func = cur.func
            if isinstance(func, ast.Attribute) and func.attr == "as_view":
                # ClassBasedView.as_view(**kwargs) - terminal, not a wrapper
                target = self.resolve_name_chain(func.value, import_map)
                return target, True, wrappers
            if len(cur.args) >= 1:
                wrapper_name = self.resolve_name_chain(func, import_map)
                wrappers.append(wrapper_name)
                cur = cur.args[0]
                continue
            # a zero-arg call we don't understand as a wrapper; stop here
            try:
                return ast.unparse(cur), False, wrappers
            except Exception:
                return "<?>", False, wrappers
        target = self.resolve_name_chain(cur, import_map)
        return target, False, wrappers

    def find_list_var(self, tree: ast.Module, name: str) -> ast.List | None:
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                t = node.targets[0]
                if isinstance(t, ast.Name) and t.id == name and isinstance(node.value, ast.List):
                    return node.value
        return None

    def parse_urlpatterns(self, dotted: str, prefix: str, namespace_chain: list[str], seen: set[str]) -> list[dict]:
        if dotted in seen:
            self.note("urls", f"skipped circular include of {dotted}")
            return []
        seen = seen | {dotted}
        parsed = self.parse_module(dotted)
        if parsed is None:
            self.note("urls", f"could not locate/parse urlconf module {dotted}")
            return []
        tree, path = parsed
        import_map = self.build_import_map(tree, dotted)
        urlpatterns_list = self.find_list_var(tree, "urlpatterns")
        if urlpatterns_list is None:
            self.note("urls", f"no top-level `urlpatterns = [...]` list literal found in {dotted}")
            return []
        routes: list[dict] = []
        for element in urlpatterns_list.elts:
            routes.extend(self.parse_url_element(element, dotted, tree, path, import_map, prefix, namespace_chain, seen))
        return routes

    def parse_url_element(self, element, dotted, tree, path, import_map, prefix, namespace_chain, seen) -> list[dict]:
        if not isinstance(element, ast.Call):
            self.note(dotted, f"unrecognized urlpatterns element at line {getattr(element,'lineno','?')}: {self._safe_unparse(element)}")
            return []
        func_name = self.resolve_name_chain(element.func, import_map)
        args = element.args
        route_str = None
        if args:
            val, resolved = literal_or_source(args[0])
            route_str = val if resolved else f"<dynamic:{val}>"
        full_prefix = prefix + (route_str or "")

        if func_name.endswith("include") and len(args) >= 1:
            inc_arg = args[0] if len(args) >= 1 else None
            # path('x/', include(...)) -> args[0] is route, args[1] is the include(...) call
            include_call = None
            for a in args[1:] + [kw.value for kw in element.keywords if kw.arg is None]:
                if isinstance(a, ast.Call):
                    include_call = a
            if include_call is None:
                self.note(dotted, f"could not find include(...) call at line {element.lineno}")
                return []
            return self.resolve_include(include_call, tree, import_map, full_prefix, namespace_chain, seen, dotted, path)

        if func_name.split(".")[-1] not in ("path", "re_path", "url"):
            self.note(dotted, f"unrecognized urlpatterns call `{func_name}` at line {element.lineno}")
            return []

        # Is the 2nd positional arg itself an include(...)? (no wrapper name match)
        if len(args) >= 2 and isinstance(args[1], ast.Call):
            inner_name = self.resolve_name_chain(args[1].func, import_map)
            if inner_name.split(".")[-1] == "include":
                return self.resolve_include(args[1], tree, import_map, full_prefix, namespace_chain, seen, dotted, path)

        name_kw = next((kw.value for kw in element.keywords if kw.arg == "name"), None)
        route_name = None
        if isinstance(name_kw, ast.Constant):
            route_name = name_kw.value

        if len(args) < 2:
            self.note(dotted, f"path() with <2 args at line {element.lineno}: {self._safe_unparse(element)}")
            return []

        target, is_cbv, wrappers = self.unwrap_view(args[1], import_map)
        view_info = self.resolve_view(target, is_cbv)
        return [{
            "pattern": full_prefix,
            "name": ".".join(namespace_chain + [route_name]) if route_name else None,
            "target": target,
            "is_class_based": is_cbv,
            "url_level_wrappers": wrappers,
            "source_file": path.relative_to(self.root).as_posix(),
            "line": element.lineno,
            **view_info,
        }]

    def resolve_include(self, include_call: ast.Call, tree, import_map, full_prefix, namespace_chain, seen, dotted, path) -> list[dict]:
        if not include_call.args:
            self.note("urls", f"include() with no args at line {include_call.lineno}")
            return []
        arg = include_call.args[0]
        namespace = None
        for kw in include_call.keywords:
            if kw.arg == "namespace" and isinstance(kw.value, ast.Constant):
                namespace = kw.value.value
        new_ns_chain = namespace_chain + [namespace] if namespace else namespace_chain

        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return self.parse_urlpatterns(arg.value, full_prefix, new_ns_chain, seen)

        if isinstance(arg, ast.Tuple) and arg.elts:
            list_expr = arg.elts[0]
            if isinstance(list_expr, ast.Name):
                list_literal = self.find_list_var(tree, list_expr.id)
                if list_literal is None:
                    self.note("urls", f"include() referenced undefined list variable `{list_expr.id}` at line {include_call.lineno}")
                    return []
                routes = []
                for element in list_literal.elts:
                    routes.extend(self.parse_url_element(element, dotted, tree, path, import_map, full_prefix, new_ns_chain, seen))
                return routes
            if isinstance(list_expr, ast.List):
                routes = []
                for element in list_expr.elts:
                    routes.extend(self.parse_url_element(element, dotted, tree, path, import_map, full_prefix, new_ns_chain, seen))
                return routes

        self.note("urls", f"unsupported include() argument shape at line {include_call.lineno}: {self._safe_unparse(arg)}")
        return []

    def _safe_unparse(self, node):
        try:
            return ast.unparse(node)
        except Exception:
            return "<?>"

    # ---------- view resolution (decorators + in-body guard calls) ----------

    def resolve_view(self, target: str, is_cbv: bool) -> dict:
        if "." not in target:
            self.note("view-resolve", f"cannot split module/function from target `{target}`")
            return {"view_module": None, "view_function": target, "decorators": [], "body_guard_calls": []}
        module_dotted, func_name = target.rsplit(".", 1)
        parsed = self.parse_module(module_dotted)
        if parsed is None:
            self.note("view-resolve", f"could not locate module `{module_dotted}` for target `{target}`")
            return {"view_module": module_dotted, "view_function": func_name, "decorators": [], "body_guard_calls": [], "audit_calls": []}
        tree, path = parsed
        import_map = self.build_import_map(tree, module_dotted)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == func_name:
                decorators = [self.resolve_name_chain(d, import_map) for d in getattr(node, "decorator_list", [])]
                guards = self.find_body_guards(node, import_map) if isinstance(node, ast.FunctionDef) else []
                audit_calls = self.find_audit_calls(node, import_map) if isinstance(node, ast.FunctionDef) else []
                return {
                    "view_module": module_dotted,
                    "view_function": func_name,
                    "view_file": path.relative_to(self.root).as_posix() if path.exists() else path.as_posix(),
                    "view_line": node.lineno,
                    "decorators": decorators,
                    "body_guard_calls": guards,
                    "audit_calls": audit_calls,
                }
        self.note("view-resolve", f"function/class `{func_name}` not found in `{module_dotted}` for target `{target}`")
        return {"view_module": module_dotted, "view_function": func_name, "decorators": [], "body_guard_calls": [], "audit_calls": []}

    def find_audit_calls(self, func: ast.FunctionDef, import_map: dict[str, str]) -> list[dict]:
        """Calls resolving to `...audit.record(...)` inside a view body.
        Kept separate from find_body_guards because 'record' does not
        match GUARD_NAME_HINTS - IB-08 needs to know independently
        whether a role check AND an audit write are both present, so
        conflating the two into one heuristic would hide exactly the
        "role check but no audit call" (or vice versa) pattern IB-08
        is about."""
        found = []
        for node in ast.walk(func):
            if node is func:
                continue
            if isinstance(node, ast.Call):
                name = self.resolve_name_chain(node.func, import_map)
                if name.endswith("audit.record"):
                    found.append({"name": name, "line": node.lineno, "source": self._safe_unparse(node)})
        return found

    def find_body_guards(self, func: ast.FunctionDef, import_map: dict[str, str]) -> list[dict]:
        found = []
        for node in ast.walk(func):
            if node is func:
                continue
            if isinstance(node, ast.Call):
                name = self.resolve_name_chain(node.func, import_map)
                if any(hint in name.lower() for hint in GUARD_NAME_HINTS):
                    found.append({"kind": "call", "name": name, "line": node.lineno, "source": self._safe_unparse(node)})
            elif isinstance(node, ast.Raise) and node.exc is not None:
                exc_name = self._safe_unparse(node.exc)
                if "PermissionDenied" in exc_name:
                    found.append({"kind": "raise", "name": exc_name, "line": node.lineno, "source": self._safe_unparse(node)})
            elif isinstance(node, ast.Compare):
                src = self._safe_unparse(node)
                if any(hint in src.lower() for hint in ("role", "is_staff", "is_superuser")):
                    found.append({"kind": "compare", "name": src, "line": node.lineno, "source": src})
        return found

    # ---------- models ----------

    def resolve_app_dir(self, app_entry: str) -> Path | None:
        if any(app_entry.startswith(p) for p in SKIP_APP_PREFIXES):
            return None
        # 'portal.apps.PortalConfig' -> 'portal' ; 'helpdesk' -> 'helpdesk'
        top = app_entry.split(".")[0]
        for base in self.search_roots:
            candidate = base / top
            if (candidate / "models.py").is_file() or (candidate / "__init__.py").is_file():
                return candidate
        return None

    def index_models(self, installed_apps: list[str]) -> list[dict]:
        models_out = []
        seen_dirs: set[str] = set()
        for app_entry in installed_apps:
            app_dir = self.resolve_app_dir(app_entry)
            if app_dir is None or str(app_dir) in seen_dirs:
                continue
            seen_dirs.add(str(app_dir))
            models_file = app_dir / "models.py"
            if not models_file.is_file():
                continue
            try:
                tree = ast.parse(models_file.read_text(encoding="utf-8"), filename=str(models_file))
            except Exception as exc:
                self.note("models", f"failed to parse {models_file}: {exc}")
                continue
            import_map = self.build_import_map(tree, f"{app_entry.split('.')[0]}.models")
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                base_names = [self.resolve_name_chain(b, import_map) for b in node.bases]
                is_model = any(b.split(".")[-1] in ("Model", "AbstractUser", "AbstractBaseUser", "PermissionsMixin") for b in base_names)
                if not is_model:
                    continue
                fields = []
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        fname = stmt.targets[0].id
                        ftype = None
                        if isinstance(stmt.value, ast.Call):
                            ftype = self.resolve_name_chain(stmt.value.func, import_map)
                        pii = any(hint in fname.lower() for hint in PII_NAME_HINTS)
                        fields.append({"name": fname, "type": ftype, "line": stmt.lineno, "pii_name_hint": pii})
                models_out.append({
                    "app_dir": app_dir.relative_to(self.root).as_posix(),
                    "file": models_file.relative_to(self.root).as_posix(),
                    "class_name": node.name,
                    "bases": base_names,
                    "line": node.lineno,
                    "fields": fields,
                })
        return models_out

    # ---------- whole-project scanning helpers ----------

    def iter_project_py_files(self):
        seen: set[Path] = set()
        for base in self.search_roots:
            for path in sorted(base.rglob("*.py")):
                if path in seen:
                    continue
                if any(part in EXCLUDE_DIR_PARTS for part in path.relative_to(base).parts):
                    continue
                seen.add(path)
                yield path

    # ---------- check 1: ORM calls that bypass post_save/post_delete signals ----------

    QUERYSET_MARKERS = (".objects", ".filter(", ".exclude(", ".all(")
    RELATED_MANAGER_RE = re.compile(r"\.\w+_set\b")

    def _looks_like_queryset_source(self, src: str) -> bool:
        return any(marker in src for marker in self.QUERYSET_MARKERS) or bool(self.RELATED_MANAGER_RE.search(src))

    def _local_assignment_sources(self, scope: ast.AST) -> dict[str, list[str]]:
        """name -> source text of every `name = <expr>` assignment found
        directly in this scope (not descending into nested defs), used to
        see through one level of `x = qs.filter(...); x.update(...)`
        indirection when checking a bare-name receiver."""
        out: dict[str, list[str]] = {}
        body = getattr(scope, "body", [])
        for node in body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        out.setdefault(target.id, []).append(self._safe_unparse(node.value))
        return out

    def find_bulk_orm_calls(self) -> list[dict]:
        """QuerySet.update()/bulk_create()/bulk_update() never fire
        post_save/post_delete - any audit mechanism relying on those
        signals (see find_signal_wiring) misses every mutation done this
        way. Flags every syntactic `.update()/.bulk_create()/.bulk_update()`
        call project-wide; `looks_like_queryset` is a heuristic (receiver
        expression, OR the expression it was assigned from earlier in the
        same enclosing function/module, mentions `.objects`, `.filter(`,
        `.exclude(`, `.all(` or a `_set` related-manager) to separate
        likely ORM calls from unrelated ones (e.g. `dict.update()`)
        without hiding the latter - both are reported, only the flag
        differs, so nothing is silently dropped.
        """
        hits = []
        for path in self.iter_project_py_files():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except Exception as exc:
                self.note("bulk-orm-scan", f"failed to parse {path}: {exc}")
                continue
            # map every function/module scope to its direct-body assignments,
            # so a bare-name receiver can be traced back one level.
            scopes: list[ast.AST] = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            scope_assignments = [(scope, self._local_assignment_sources(scope)) for scope in scopes]
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("update", "bulk_create", "bulk_update"):
                    receiver_src = self._safe_unparse(node.func.value)
                    looks_like_queryset = self._looks_like_queryset_source(receiver_src)
                    traced_from = None
                    if not looks_like_queryset and isinstance(node.func.value, ast.Name):
                        # look for the innermost enclosing scope that assigns this name
                        for scope, assigns in scope_assignments:
                            if node.func.value.id in assigns:
                                candidates = assigns[node.func.value.id]
                                if any(self._looks_like_queryset_source(c) for c in candidates):
                                    looks_like_queryset = True
                                    traced_from = next(c for c in candidates if self._looks_like_queryset_source(c))
                    hits.append({
                        "file": path.relative_to(self.root).as_posix(),
                        "line": node.lineno,
                        "method": node.func.attr,
                        "receiver_source": receiver_src,
                        "receiver_traced_to": traced_from,
                        "call_source": self._safe_unparse(node),
                        "looks_like_queryset": looks_like_queryset,
                    })
        return hits

    # ---------- check 2: audit-signal wiring and per-model coverage ----------

    def find_app_label_filter(self, dotted_handler: str) -> dict:
        if "." not in dotted_handler:
            return {"resolved": False, "reason": "not a dotted module.function reference"}
        module_dotted, func_name = dotted_handler.rsplit(".", 1)
        parsed = self.parse_module(module_dotted)
        if parsed is None:
            return {"resolved": False, "reason": f"could not locate module {module_dotted}"}
        tree, path = parsed
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Compare) and "app_label" in self._safe_unparse(sub):
                        allowed = None
                        for cmp_node in ast.walk(sub):
                            if isinstance(cmp_node, (ast.Tuple, ast.List)):
                                val, ok = literal_or_source(cmp_node)
                                if ok:
                                    allowed = val
                        return {"resolved": True, "file": path.relative_to(self.root).as_posix(), "line": sub.lineno,
                                "source": self._safe_unparse(sub), "allowed_app_labels": allowed}
                return {"resolved": True, "file": path.relative_to(self.root).as_posix(), "line": node.lineno,
                        "allowed_app_labels": None,
                        "note": "no app_label filter found in handler body; handler applies unconditionally to every sender"}
        return {"resolved": False, "reason": f"function {func_name} not found in {module_dotted}"}

    def find_signal_wiring(self, installed_apps: list[str]) -> dict:
        connections = []
        seen_apps: set[str] = set()
        for app_entry in installed_apps:
            app_dir = self.resolve_app_dir(app_entry)
            if app_dir is None or str(app_dir) in seen_apps:
                continue
            seen_apps.add(str(app_dir))
            apps_py = app_dir / "apps.py"
            if not apps_py.is_file():
                continue
            try:
                tree = ast.parse(apps_py.read_text(encoding="utf-8"), filename=str(apps_py))
            except Exception as exc:
                self.note("signal-wiring", f"failed to parse {apps_py}: {exc}")
                continue
            import_map = self.build_import_map(tree, f"{app_entry.split('.')[0]}.apps")
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "connect":
                    signal_name = self.resolve_name_chain(node.func.value, import_map)
                    handler = self.resolve_name_chain(node.args[0], import_map) if node.args else None
                    sender_kw = None
                    dispatch_uid = None
                    for kw in node.keywords:
                        if kw.arg == "sender":
                            sender_kw = self._safe_unparse(kw.value)
                        if kw.arg == "dispatch_uid":
                            v, _ = literal_or_source(kw.value)
                            dispatch_uid = v
                    connections.append({
                        "file": apps_py.relative_to(self.root).as_posix(),
                        "line": node.lineno,
                        "signal": signal_name,
                        "handler": handler,
                        "sender_kwarg": sender_kw,
                        "dispatch_uid": dispatch_uid,
                    })
        if not connections:
            self.note("signal-wiring", "no `.connect(...)` calls found in any local app's apps.py")
        handler_filters = {}
        for c in connections:
            handler = c["handler"]
            if handler and handler not in handler_filters:
                handler_filters[handler] = self.find_app_label_filter(handler)
        return {"connections": connections, "handler_app_label_filters": handler_filters}

    def compute_model_coverage(self, models: list[dict], signal_wiring: dict) -> list[dict]:
        mutation_labels: set[str] = set()
        unconditional_mutation_handler = False
        any_mutation_signal = False
        for c in signal_wiring.get("connections", []):
            if c["signal"].split(".")[-1] in ("post_save", "post_delete"):
                any_mutation_signal = True
                filt = signal_wiring["handler_app_label_filters"].get(c["handler"], {})
                if filt.get("allowed_app_labels"):
                    mutation_labels.update(filt["allowed_app_labels"])
                elif filt.get("note", "").startswith("no app_label filter"):
                    unconditional_mutation_handler = True
        if not any_mutation_signal:
            self.note("signal-wiring", "no post_save/post_delete connections found; per-model mutation-audit coverage cannot be confirmed for any model")
        coverage = []
        for m in models:
            app_label = Path(m["app_dir"]).name
            covered = any_mutation_signal and (unconditional_mutation_handler or app_label in mutation_labels)
            coverage.append({
                "app_label": app_label,
                "class_name": m["class_name"],
                "file": m["file"],
                "covered_by_post_save_post_delete_signals": covered,
            })
        return coverage

    # ---------- check 3: local_acl.py / audit.py structured extraction ----------

    def _find_module_by_content(self, name_hint: str, content_re: str) -> Path | None:
        """Первый .py проекта, чьё имя содержит name_hint ИЛИ содержимое матчит content_re."""
        rx = re.compile(content_re)
        by_name = None
        for path in self.iter_project_py_files():
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                continue
            if name_hint in path.name.lower() and by_name is None and rx.search(text):
                by_name = path
        if by_name:
            return by_name
        for path in self.iter_project_py_files():
            try:
                if rx.search(path.read_text(encoding="utf-8")):
                    return path
            except Exception:
                continue
        return None

    def index_log_protection(self) -> dict:
        """Структурная выжимка модуля прав доступа (set_reader_access/chmod) и
        модуля аудита (шифрованная запись журнала). Модули ищутся по всему
        проекту (имя + содержимое), а не по жёстко заданному пути."""
        out = {"local_acl_configure_calls": [], "audit_functions": [], "acl_module": None, "audit_module": None}
        acl_path = self._find_module_by_content("acl", r"def set_reader_access\(|SetNamedSecurityInfo|os\.chmod\(")
        if acl_path is not None:
            out["acl_module"] = acl_path.relative_to(self.root).as_posix()
            tree = ast.parse(acl_path.read_text(encoding="utf-8"), filename=str(acl_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == "configure":
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call) and self._safe_unparse(sub.func).endswith("set_reader_access") and len(sub.args) >= 2:
                            path_expr = self._safe_unparse(sub.args[0])
                            access_val, resolved = literal_or_source(sub.args[1])
                            out["local_acl_configure_calls"].append({"path_expr": path_expr, "access": access_val, "resolved": resolved, "line": sub.lineno})
        else:
            self.note("log-protection", "модуль управления правами доступа (set_reader_access/chmod) не найден")

        audit_path = self._find_module_by_content("audit", r"AESGCM|Fernet|ChaCha20Poly1305")
        if audit_path is None:
            audit_path = self._find_module_by_content("audit", r"def record\(")
        if audit_path is not None:
            out["audit_module"] = audit_path.relative_to(self.root).as_posix()
            tree = ast.parse(audit_path.read_text(encoding="utf-8"), filename=str(audit_path))
            import_map = self.build_import_map(tree, self.path_to_dotted(audit_path))
            for node in tree.body:
                if isinstance(node, ast.FunctionDef):
                    calls = [self.resolve_name_chain(c.func, import_map) for c in ast.walk(node) if isinstance(c, ast.Call)]
                    uses_aead = any(c.split(".")[-1] in ("AESGCM", "Fernet", "ChaCha20Poly1305", "AESCCM") for c in calls)
                    has_write = any(c.split(".")[-1] in ("write_bytes", "write_text") for c in calls)
                    has_rename = any(c.split(".")[-1] in ("rename", "replace") for c in calls)
                    out["audit_functions"].append({
                        "function": node.name,
                        "line": node.lineno,
                        "uses_aead": uses_aead,
                        "has_write_call": has_write,
                        "has_rename_call": has_rename,
                        "atomic_write_pattern": has_write and has_rename,
                    })
        else:
            self.note("log-protection", "модуль аудита (шифрованная запись журнала) не найден")
        return out

    # ---------- check 4: token lifecycle / revocation on role or password change ----------

    def index_token_lifecycle(self) -> dict:
        result = {"issuers": [], "validators": [], "role_or_password_change_functions": []}
        revocation_hints = ("version", "revoke", "revoked", "blocklist", "blacklist", "invalidat", "session", "auth_hash")
        change_name_hints = ("change_role", "reset_password", "password_change", "set_password")
        for path in self.iter_project_py_files():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except Exception:
                continue
            import_map = self.build_import_map(tree, self.path_to_dotted(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef):
                    continue
                calls = [self.resolve_name_chain(c.func, import_map) for c in ast.walk(node) if isinstance(c, ast.Call)]
                if any(c.endswith("signing.dumps") for c in calls):
                    embeds_exp = any(
                        isinstance(sub, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "exp" for k in sub.keys)
                        for sub in ast.walk(node)
                    )
                    result["issuers"].append({"function": node.name, "file": path.relative_to(self.root).as_posix(), "line": node.lineno, "embeds_exp_claim": embeds_exp})
                if any(c.endswith("signing.loads") for c in calls):
                    checks_exp = any(
                        isinstance(sub, (ast.Subscript, ast.Call)) and ("'exp'" in self._safe_unparse(sub) or '"exp"' in self._safe_unparse(sub))
                        for sub in ast.walk(node)
                    )
                    result["validators"].append({"function": node.name, "file": path.relative_to(self.root).as_posix(), "line": node.lineno, "checks_exp_claim": checks_exp})
                if any(hint in node.name.lower() for hint in change_name_hints):
                    hits = sorted({c for c in calls if any(h in c.lower() for h in revocation_hints)})
                    result["role_or_password_change_functions"].append({"function": node.name, "file": path.relative_to(self.root).as_posix(), "line": node.lineno, "revocation_related_calls": hits})
        return result

    # ---------- check 5: failed-login throttling ----------

    def index_login_throttling(self, settings_index: dict) -> dict:
        apps = settings_index.get("INSTALLED_APPS", {}).get("value") or []
        middleware = settings_index.get("MIDDLEWARE", {}).get("value") or []
        hints = ("axes", "ratelimit", "defender", "lockout", "throttl", "brute")
        apps_hits = [a for a in apps if isinstance(a, str) and any(h in a.lower() for h in hints)]
        mw_hits = [m for m in middleware if isinstance(m, str) and any(h in m.lower() for h in hints)]
        return {
            "searched_installed_apps": apps,
            "searched_middleware": middleware,
            "installed_apps_hits": apps_hits,
            "middleware_hits": mw_hits,
            "throttling_mechanism_found": bool(apps_hits or mw_hits),
        }

    # ---------- check 6: password validators beyond minimum length ----------

    PASSWORD_REUSE_RE = re.compile(
        r"(password[\w_]{0,20}(history|reuse|previously.used)|(?:history|reuse)[\w_]{0,20}password|old_password)",
        re.IGNORECASE,
    )

    def index_password_validators(self, settings_index: dict) -> dict:
        entry = settings_index.get("AUTH_PASSWORD_VALIDATORS", {})
        validators = entry.get("value") if entry.get("resolved") else None
        names = [v["NAME"] for v in validators if isinstance(v, dict) and "NAME" in v] if isinstance(validators, list) else []
        reuse_hits = []
        for path in self.iter_project_py_files():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except Exception:
                continue
            for lineno, line in enumerate(lines, start=1):
                if self.PASSWORD_REUSE_RE.search(line):
                    reuse_hits.append({"file": path.relative_to(self.root).as_posix(), "line": lineno, "text": line.strip()})
        return {
            "configured_validators": names,
            "resolved_statically": entry.get("resolved", False),
            "covers_minimum_length": any(n.endswith("MinimumLengthValidator") for n in names),
            "covers_common_password_rejection": any(n.endswith("CommonPasswordValidator") for n in names),
            "covers_all_numeric_rejection": any(n.endswith("NumericPasswordValidator") for n in names),
            "covers_password_reuse_block": bool(reuse_hits),
            "password_reuse_evidence": reuse_hits,
        }

    # ---------- check 7: auxiliary (non-Django) deploy/TLS config files ----------

    def index_auxiliary_configs(self) -> dict:
        """IB-03 explicitly requires checking TLS version/cipher/redirect
        config, which in this project lives in proxy.json, not in Django's
        settings.py - settings.py alone (SECURE_SSL_REDIRECT etc.) is not
        the whole picture for this project's transport security posture.
        Generalized slightly: any *.json file directly at the project root
        is included verbatim, so this isn't a one-off hardcoded exception
        for a filename that happens to exist in this particular repo.
        """
        out = {}
        found_any = False
        for path in sorted(self.root.glob("*.json")):
            try:
                out[path.name] = json.loads(path.read_text(encoding="utf-8"))
                found_any = True
            except Exception as exc:
                self.note("auxiliary-config", f"failed to parse {path}: {exc}")
        if not found_any:
            self.note("auxiliary-config", "no *.json config files found at project root (e.g. no proxy.json)")
        return out

    # ---------- check 8: password written outside the configured hasher ----------

    def find_password_bypass_writes(self) -> list[dict]:
        """IB-04 explicitly calls out 'any legacy user-creation path
        bypassing the standard hashing (direct password write, custom
        save())'. `set_password()` is what routes a password through
        PASSWORD_HASHERS; a direct `.password = ...` assignment, or
        `Model.objects.create(password=...)` (as opposed to the built-in
        `create_user`, which internally calls set_password and is not
        flagged here) does not.
        """
        hits = []
        for path in self.iter_project_py_files():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Attribute) and target.attr == "password":
                            hits.append({"file": path.relative_to(self.root).as_posix(), "line": node.lineno,
                                         "kind": "direct_attribute_assign", "source": self._safe_unparse(node)})
                if isinstance(node, ast.Call):
                    func_src = self._safe_unparse(node.func)
                    if func_src.endswith(".objects.create"):
                        for kw in node.keywords:
                            if kw.arg == "password":
                                hits.append({"file": path.relative_to(self.root).as_posix(), "line": node.lineno,
                                             "kind": "objects.create(password=...)", "source": self._safe_unparse(node)})
        return hits

    # ---------- check 9: regulatory references in docs (IB-06) ----------

    REGULATORY_REFERENCES = {
        "law_cybersecurity_418-V_2015-11-24": ("418-V",),
        "law_personal_data_94-V_2013-05-21": ("94-V",),
        "government_resolution_832_2016-12-20": ("832",),
        "gost_rk_iso_iec_27001-2023": ("27001",),
        "gost_rk_iso_iec_27002-2023": ("27002",),
        "gost_rk_1073-2007": ("1073-2007",),
    }

    def index_regulatory_references(self) -> dict:
        """Line-level evidence per reference, not a bare boolean: a
        substring match against a whole concatenated document blob would
        say a reference was "found" without saying where, which is not
        enough to double as report evidence (docs/04-report-schema.md
        requires file+line for every finding, including a clean/pass
        one) and is exactly the kind of check that burned this indexer
        before on password-reuse (see find_password_bypass_writes'
        docstring history) - a coincidental substring match elsewhere in
        the project would otherwise be indistinguishable from a real hit.
        """
        doc_files = []
        docx_files = []
        readme = self.root / "README.md"
        if readme.is_file():
            doc_files.append(readme)
        docs_dir = self.root / "docs"
        if docs_dir.is_dir():
            for p in sorted(docs_dir.iterdir()):
                if p.suffix.lower() in (".md", ".txt"):
                    doc_files.append(p)
                elif p.suffix.lower() == ".docx":
                    docx_files.append(p)
                elif p.suffix.lower() in (".doc", ".pdf"):
                    self.note("regulatory-references", f"{p.relative_to(self.root).as_posix()} not parsed (binary format) - checked separately or flagged as a limitation")
        searched = []
        lines_by_file: dict[str, list[str]] = {}
        for f in doc_files:
            try:
                lines_by_file[f.relative_to(self.root).as_posix()] = f.read_text(encoding="utf-8", errors="ignore").splitlines()
                searched.append(f.relative_to(self.root).as_posix())
            except Exception as exc:
                self.note("regulatory-references", f"failed to read {f}: {exc}")
        if not searched:
            self.note("regulatory-references", "no README.md or docs/*.{md,txt} found to search")
        evidence: dict[str, list[dict]] = {key: [] for key in self.REGULATORY_REFERENCES}
        for rel_path, lines in lines_by_file.items():
            for lineno, line in enumerate(lines, start=1):
                for key, markers in self.REGULATORY_REFERENCES.items():
                    if any(m in line for m in markers):
                        evidence[key].append({"file": rel_path, "line": lineno, "text": line.strip()})
        reference_found = {key: bool(hits) for key, hits in evidence.items()}

        # .docx documents (ТЗ / техническая спецификация) - parsed from the
        # OOXML package with stdlib only (zipfile + ElementTree). Evidence is
        # paragraph-level ("line" = 1-based paragraph index in word/document.xml),
        # kept in a separate sub-dict so README line evidence stays byte-exact.
        docx: dict[str, dict] = {}
        for p in docx_files:
            rel = p.relative_to(self.root).as_posix()
            try:
                paragraphs = self.docx_paragraphs(p)
                hyperlinks = self.docx_hyperlinks(p)
            except Exception as exc:
                self.note("regulatory-references", f"{rel} not parsed (binary format): {exc}")
                continue
            d_evidence: dict[str, list[dict]] = {key: [] for key in self.REGULATORY_REFERENCES}
            for pno, text in enumerate(paragraphs, start=1):
                for key, markers in self.REGULATORY_REFERENCES.items():
                    if any(m in text for m in markers):
                        d_evidence[key].append({"file": rel, "paragraph": pno, "text": text.strip()[:300]})
            d_found = {key: bool(hits) for key, hits in d_evidence.items()}
            docx[rel] = {
                "paragraphs_total": len(paragraphs),
                "hyperlinks": hyperlinks,
                "reference_found": d_found,
                "reference_evidence": d_evidence,
                "all_six_present": all(d_found.values()),
            }
        return {
            "searched_files": searched,
            "reference_found": reference_found,
            "reference_evidence": evidence,
            "all_six_present": all(reference_found.values()),
            "docx": docx,
        }

    _W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

    def docx_paragraphs(self, path: Path) -> list[str]:
        """Plain text of every <w:p> in word/document.xml (tables included),
        in document order. No external libraries."""
        with zipfile.ZipFile(path) as z:
            root = ET.fromstring(z.read("word/document.xml"))
        out: list[str] = []
        for p in root.iter(self._W_NS + "p"):
            texts = [t.text or "" for t in p.iter(self._W_NS + "t")]
            out.append("".join(texts))
        return out

    def docx_hyperlinks(self, path: Path) -> list[str]:
        """External hyperlink targets declared in word/_rels/document.xml.rels."""
        with zipfile.ZipFile(path) as z:
            try:
                rels = z.read("word/_rels/document.xml.rels").decode("utf-8", errors="ignore")
            except KeyError:
                return []
        return sorted(set(re.findall(r'Target="(https?://[^"]+)"', rels)))

    # ---------- whole-project inventory (completeness evidence, ТЗ 4.4.1/4.4.3) ----------

    INVENTORY_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "runtime", "agent", ".claude"}
    # The agent's own files that live outside agent/ (its CI step) are not part
    # of the project under check. Skipped by exact path, not by directory: the
    # target's own .github/workflows/* stay in the inventory as "ci" input.
    AGENT_OWN_FILES = {".github/workflows/ib-check.yml"}
    # First match wins: "ci" (matched by path prefix) must precede "config",
    # otherwise every workflow .yml is claimed by its suffix first.
    INVENTORY_CATEGORIES = (
        ("ci", (".github/workflows",)),
        ("code", (".py",)),
        ("config", (".json", ".toml", ".ini", ".cfg", ".yml", ".yaml", ".conf", ".env")),
        ("dependencies", ("requirements.txt", "requirements.in", "requirements.lock", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock")),
        ("docs", (".md", ".txt", ".docx", ".rst", ".pdf")),
        ("templates", (".html", ".htm")),
        ("static", (".js", ".css", ".svg", ".png", ".jpg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".map")),
        ("locale", (".po", ".mo")),
        ("shell", (".sh", ".ps1", ".bat", ".cmd")),
    )

    def index_inventory(self) -> dict:
        """Every regular file in the project (except VCS/cache/runtime dirs)
        with size and coarse category. This is the agent's proof that the
        WHOLE project was enumerated (not just the diff) and the basis for
        per-requirement file selection in the LLM context builder."""
        files: list[dict] = []
        by_category: dict[str, dict] = {}
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(self.root)
            if any(part in self.INVENTORY_SKIP_DIRS for part in rel.parts):
                continue
            rel_s = rel.as_posix()
            if rel_s in self.AGENT_OWN_FILES:
                continue
            category = "other"
            for cat, markers in self.INVENTORY_CATEGORIES:
                if cat == "dependencies" and path.name in markers:
                    category = cat
                    break
                if cat == "ci" and rel_s.startswith(markers):
                    category = cat
                    break
                if cat not in ("dependencies", "ci") and path.suffix.lower() in markers:
                    category = cat
                    break
            size = path.stat().st_size
            files.append({"path": rel_s, "size": size, "category": category})
            bucket = by_category.setdefault(category, {"files": 0, "bytes": 0})
            bucket["files"] += 1
            bucket["bytes"] += size
        return {"files": files, "total_files": len(files), "total_bytes": sum(f["size"] for f in files), "by_category": by_category}

    # ---------- guard/decorator body resolution ----------

    def index_guard_definitions(self, routes: list[dict]) -> dict:
        """Resolve the actual source of every project-local guard-like
        function referenced anywhere in `routes` (as a decorator, e.g.
        `portal.access.manage_required`, or as an in-body guard call,
        e.g. `access.operator_required`/`administrator`).

        Why this exists: `routes[].decorators` and `routes[].body_guard_calls`
        only give a NAME (`portal.access.manage_required`). Judging IB-01
        (does this guard actually check role=='administrator', or does it
        check `is_staff`, which this codebase also grants to operators)
        requires the guard function's real body, not its name. Without
        this, module 3 would have to fall back to re-reading portal/access.py
        directly for IB-01, defeating the "index.json as primary input"
        design. Framework/third-party guards (login_required, require_GET,
        etc.) won't resolve to a local file and are silently skipped here -
        their absence from this dict is itself informative (nothing project-
        specific to inspect there).
        """
        worklist: list[str] = []
        seen: set[str] = set()
        for r in routes:
            for name in r.get("decorators") or []:
                if name not in seen:
                    seen.add(name)
                    worklist.append(name)
            for g in r.get("body_guard_calls") or []:
                if g.get("kind") == "call" and g["name"] not in seen:
                    seen.add(g["name"])
                    worklist.append(g["name"])
        out: dict[str, dict] = {}
        while worklist:
            name = worklist.pop(0)
            if "." not in name:
                continue
            module_dotted, func_name = name.rsplit(".", 1)
            parsed = self.parse_module(module_dotted)
            if parsed is None:
                continue
            tree, path = parsed
            import_map = self.build_import_map(tree, module_dotted)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == func_name:
                    try:
                        source = path.read_text(encoding="utf-8")
                        snippet = ast.get_source_segment(source, node)
                    except Exception:
                        snippet = None
                    out[name] = {"file": path.relative_to(self.root).as_posix(), "line": node.lineno, "source": snippet}
                    # one more hop: guard-like calls made from inside this
                    # guard's own body (e.g. admin_required -> administrator())
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Call):
                            called = self.resolve_name_chain(sub.func, import_map)
                            if "." not in called:
                                # bare name: not imported, so (if it resolves
                                # at all) it's defined in this same module
                                called = f"{module_dotted}.{called}"
                            if called not in seen and any(h in called.lower() for h in GUARD_NAME_HINTS):
                                seen.add(called)
                                worklist.append(called)
                    break
        return out

    # ---------- top level ----------

    def build(self) -> dict:
        settings_module = self.find_settings_module()
        settings_index: dict = {}
        routes: list[dict] = []
        models: list[dict] = []
        signal_wiring: dict = {}
        model_coverage: list[dict] = []
        urlconf_module = None
        if settings_module:
            settings_index = self.index_settings(settings_module)
            urlconf_entry = settings_index.get("ROOT_URLCONF")
            if urlconf_entry and urlconf_entry["resolved"]:
                urlconf_module = urlconf_entry["value"]
                routes = self.parse_urlpatterns(urlconf_module, "", [], set())
            else:
                self.note("urls", "ROOT_URLCONF not statically resolvable")
            apps_entry = settings_index.get("INSTALLED_APPS")
            if apps_entry and apps_entry["resolved"]:
                models = self.index_models(apps_entry["value"])
                signal_wiring = self.find_signal_wiring(apps_entry["value"])
                model_coverage = self.compute_model_coverage(models, signal_wiring)
            else:
                self.note("models", "INSTALLED_APPS not statically resolvable")
        def rel_or_none(dotted):
            p = self.module_to_file(dotted) if dotted else None
            return p.relative_to(self.root).as_posix() if p else None

        return {
            "meta": {
                "root": str(self.root),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "settings_module": settings_module,
                "settings_file": rel_or_none(settings_module),
                "urlconf_module": urlconf_module,
                "urlconf_file": rel_or_none(urlconf_module),
                "search_roots": [str(p) for p in self.search_roots],
            },
            "inventory": self.index_inventory(),
            "settings": settings_index,
            "routes": routes,
            "guard_definitions": self.index_guard_definitions(routes),
            "models": models,
            "bulk_orm_calls": self.find_bulk_orm_calls(),
            "signal_wiring": signal_wiring,
            "model_audit_coverage": model_coverage,
            "log_protection": self.index_log_protection(),
            "token_lifecycle": self.index_token_lifecycle(),
            "login_throttling": self.index_login_throttling(settings_index),
            "password_validators": self.index_password_validators(settings_index),
            "auxiliary_configs": self.index_auxiliary_configs(),
            "password_bypass_writes": self.find_password_bypass_writes(),
            "regulatory_references": self.index_regulatory_references(),
            "notes": [asdict(n) for n in self.notes],
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Static Django project indexer")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--out", default=None, help="write JSON here; default stdout")
    args = parser.parse_args(argv)
    root = Path(args.project_root).resolve()
    indexer = Indexer(root)
    result = indexer.build()
    text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote index to {args.out}", file=sys.stderr)
        print(
            f"routes={len(result['routes'])} models={len(result['models'])} "
            f"bulk_orm_calls={len(result['bulk_orm_calls'])} "
            f"signal_connections={len(result['signal_wiring'].get('connections', []))} "
            f"notes={len(result['notes'])}",
            file=sys.stderr,
        )
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
