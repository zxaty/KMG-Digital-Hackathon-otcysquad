"""Сквозные тесты CLI (agent/main.py): коды завершения, отчёт, дедлайн,
недоступность модели, отсутствие секретов. Модель — локальный фейковый
сервер (tests/fake_llm_server.py) или режим none.

Запуск: python3 -m unittest discover -s agent/tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = AGENT_DIR.parent
CLEAN_ROOT = AGENT_DIR / "tests" / "fixtures" / "clean_project"
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(AGENT_DIR / "tests"))

from fake_llm_server import FakeLLMServer  # noqa: E402
import report as report_mod  # noqa: E402

REQUIRED_TOP = {"meta", "summary", "violations", "additional_findings", "limitations", "resources"}
ALL_IDS = {f"IB-0{i}" for i in range(1, 9)}


def run_agent(project_root: Path, out_dir: Path, *extra, env_extra=None, timeout=600):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LLM_", "GITHUB_"))}
    env.update(env_extra or {})
    env["PYTHONIOENCODING"] = "utf-8"   # вывод агента — всегда UTF-8, независимо от кодовой страницы консоли
    cmd = [sys.executable, str(AGENT_DIR / "main.py"), "--project-root", str(project_root),
           "--out-json", str(out_dir / "report.json"), "--out-md", str(out_dir / "report.md"), *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=timeout)
    return proc


def load_report(out_dir: Path) -> dict:
    return json.loads((out_dir / "report.json").read_text(encoding="utf-8"))


def assert_report_shape(tc: unittest.TestCase, rep: dict):
    tc.assertTrue(REQUIRED_TOP <= set(rep))
    tc.assertEqual(set(rep["summary"]["requirements_status"]), ALL_IDS)
    tc.assertEqual({r["id"] for r in rep["summary"]["requirements"]}, ALL_IDS)
    table = {0: ("pass", 0), 1: ("fail", None)}
    code = rep["summary"]["exit_code"]
    tc.assertIn(code, table)
    tc.assertEqual(rep["summary"]["overall_result"], table[code][0])
    if code == 0:
        tc.assertEqual(rep["summary"]["violations_count"], 0)
    for v in rep["violations"]:
        for key in ("id", "requirement_id", "requirement_display_id", "requirement_text", "location", "evidence", "justification", "severity", "recommendation"):
            tc.assertIn(key, v)
            tc.assertTrue(v[key] not in (None, "") or key == "evidence", (key, v))
        tc.assertTrue(v["location"]["file"])
        tc.assertIsInstance(v["location"]["line"], int)
        tc.assertTrue(v["requirement_display_id"].startswith("ИБ-0"))
    tc.assertTrue(rep["meta"]["commit"])
    for r in rep["summary"]["requirements"]:
        tc.assertIn(r["status"], ("pass", "violation", "insufficient_data", "not_checked"), r)
        if r.get("insufficient_data_reason"):
            tc.assertEqual(r["status"], "insufficient_data", r)   # без противоречивых пар статус + «недостаточно данных»
        if r.get("analysis_warning"):
            tc.assertTrue(any(l.startswith(r["display_id"] + ":") for l in rep["limitations"]), (r["id"], rep["limitations"]))


class MainRulesOnlyTests(unittest.TestCase):
    def test_real_project_rules_only_exit_1_and_valid_report(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(PROJECT_ROOT, out, "--provider", "none")
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rep = load_report(out)
            assert_report_shape(self, rep)
            self.assertEqual(rep["summary"]["exit_code"], 1)
            self.assertGreaterEqual(rep["summary"]["violations_count"], 10)
            self.assertEqual(rep["summary"]["requirements_status"]["IB-06"], "pass")
            self.assertEqual(rep["summary"]["requirements_status"]["IB-08"], "violation")
            # журнал шага содержит код, число нарушений и перечень требований (ТЗ 4.3.5)
            self.assertIn("код завершения 1", proc.stdout)
            self.assertIn("Нарушены требования: ИБ-01", proc.stdout)
            self.assertIn("::error::", proc.stdout)
            md = (out / "report.md").read_text(encoding="utf-8")
            self.assertIn("ИБ-08", md)
            self.assertIn("export_json", md)
            # фрагмент-доказательство для функции включает декораторы и тело
            ib08 = next(v for v in rep["violations"] if v["requirement_id"] == "IB-08")
            self.assertIn("@login_required", ib08["evidence"])
            self.assertIn("def export_json", ib08["evidence"])
            self.assertIn("people_rows()", ib08["evidence"])
            self.assertNotIn("login_required, login_required", ib08["justification"])
            # замечания ТС — в отдельном разделе и на русском
            self.assertGreaterEqual(len(rep["additional_findings"]), 8)
            self.assertFalse(any("No failed-login" in a["description"] for a in rep["additional_findings"]))

    def test_clean_project_rules_only_exit_0(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(CLEAN_ROOT, out, "--provider", "none")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            rep = load_report(out)
            assert_report_shape(self, rep)
            self.assertEqual(rep["summary"]["violations_count"], 0)
            self.assertEqual(set(rep["summary"]["requirements_status"].values()), {"pass"})
            self.assertIn("::notice::", proc.stdout)

    def test_report_contains_no_training_passwords(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            run_agent(PROJECT_ROOT, out, "--provider", "none")
            text = (out / "report.json").read_text(encoding="utf-8") + (out / "report.md").read_text(encoding="utf-8")
            self.assertNotIn("Training-2026!", text)
            self.assertNotIn("Service-2026!", text)


class MainWithFakeModelTests(unittest.TestCase):
    def test_model_findings_are_merged_and_spec_gaps_reported(self):
        def responder(body):
            user = next(m["content"] for m in body["messages"] if m["role"] == "user")
            rid = user.splitlines()[0].split(":")[0].replace("Requirement ", "").strip()
            resp = {"status": "pass", "summary": f"проверено {rid}", "violations": [], "rule_findings_review": [],
                    "spec_gaps": [], "need_files": [], "checked_files": ["portal/views.py"], "insufficient_data_reason": None}
            if rid == "IB-07":
                resp["status"] = "violation"
                resp["violations"] = [{"location": {"file": "portal/views.py", "line": 81, "function": "bulk_status"},
                                       "justification": "QuerySet.update() обходит post_save.", "severity": "high",
                                       "confidence": "confirmed", "recommendation": "Регистрировать явно."}]
                resp["spec_gaps"] = [{"location": {"file": "portal/views.py", "line": 60, "function": "ticket_detail"},
                                      "category": "data-handling-detail", "description": "нет контроля параллельного изменения (ТС 4.11.3)", "severity": "medium"}]
                resp["rule_findings_review"] = [{"id": "RF-1", "verdict": "confirm", "comment": "подтверждаю", "counter_evidence": None}]
            if rid == "IB-02":
                # галлюцинация: строки 9999 нет — должна быть отклонена, но статус останется violation по правилам
                resp["status"] = "violation"
                resp["violations"] = [{"location": {"file": "portal/views.py", "line": 9999, "function": "x"},
                                       "justification": "выдумано", "severity": "low", "recommendation": "нет"}]
            return json.dumps(resp, ensure_ascii=False)

        with FakeLLMServer("ok", responder=responder) as srv, tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(PROJECT_ROOT, out, "--provider", "deepseek", "--base-url", srv.base_url, "--model", "fake",
                             env_extra={"LLM_API_KEY": "k"})
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rep = load_report(out)
            assert_report_shape(self, rep)
            self.assertEqual(len(srv.requests), 7)  # IB-06 без модели
            self.assertEqual(rep["meta"]["model"], "deepseek/fake")
            self.assertEqual(rep["resources"]["llm"]["calls"], 7)
            self.assertGreater(rep["resources"]["llm"]["total_tokens"], 0)
            merged = [v for v in rep["violations"] if v["location"]["file"] == "portal/views.py" and v["location"]["line"] == 81]
            self.assertEqual(len(merged), 1)
            self.assertEqual(merged[0]["source"], "rule+llm")
            gaps = [a for a in rep["additional_findings"] if a.get("category") == "data-handling-detail" and a["location"]["line"] == 60]
            self.assertEqual(len(gaps), 1)
            self.assertTrue(any("отклонено 1 кандидат" in l for l in rep["limitations"]), rep["limitations"])
            # промпт содержит исходники и карту проекта
            prompts = [next(m["content"] for m in r["body"]["messages"] if m["role"] == "user") for r in srv.requests]
            self.assertTrue(all("project_map" in p for p in prompts))
            self.assertTrue(all("=== rule_findings" in p for p in prompts))
            self.assertTrue(all("=== Навык проверки" in p for p in prompts))
            system = next(m["content"] for m in srv.requests[0]["body"]["messages"] if m["role"] == "system")
            self.assertEqual(system, (AGENT_DIR / "prompts" / "system.md").read_text(encoding="utf-8").strip())
            ib01 = next(p for p in prompts if p.startswith("Requirement IB-01:"))
            self.assertIn("----- portal/views.py", ib01)
            self.assertIn("----- demodesk/config/urls.py", ib01)

    def test_model_unavailable_exit_2_no_report(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(PROJECT_ROOT, out, "--provider", "deepseek", "--base-url", "http://127.0.0.1:9/v1",
                             "--model", "fake", "--max-retries", "0", env_extra={"LLM_API_KEY": "k", "LLM_TIMEOUT": "3"})
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertFalse((out / "report.json").exists())
            self.assertIn("::error::", proc.stdout)
            self.assertIn("недоступна", proc.stdout)

    def test_missing_api_key_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(PROJECT_ROOT, out, "--provider", "deepseek")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertFalse((out / "report.json").exists())

    def test_deadline_produces_partial_report(self):
        with FakeLLMServer("echo_prompt") as srv, tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(PROJECT_ROOT, out, "--provider", "deepseek", "--base-url", srv.base_url, "--model", "fake",
                             "--deadline-minutes", "0.0001", env_extra={"LLM_API_KEY": "k"})
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rep = load_report(out)
            self.assertTrue(rep["meta"]["timed_out"])
            self.assertEqual(len(srv.requests), 0)
            self.assertTrue(any("Дедлайн" in l for l in rep["limitations"]))
            modes = {r["analysis_mode"] for r in rep["summary"]["requirements"] if r["id"] != "IB-06"}
            self.assertEqual(modes, {"rules-only (timeout)"})

    def test_garbage_model_output_insufficient_data_and_flags(self):
        with FakeLLMServer("garbage") as srv, tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(CLEAN_ROOT, out, "--provider", "deepseek", "--base-url", srv.base_url, "--model", "fake",
                             env_extra={"LLM_API_KEY": "k"})
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            rep = load_report(out)
            statuses = rep["summary"]["requirements_status"]
            self.assertEqual(statuses["IB-06"], "pass")
            self.assertEqual({v for k, v in statuses.items() if k != "IB-06"}, {"insufficient_data"})
            self.assertIn("::warning::", proc.stdout)
            proc2 = run_agent(CLEAN_ROOT, out, "--provider", "deepseek", "--base-url", srv.base_url, "--model", "fake",
                              "--fail-on-insufficient", env_extra={"LLM_API_KEY": "k"})
            self.assertEqual(proc2.returncode, 1)


class MainModelInteractionTests(unittest.TestCase):
    def test_dispute_and_need_files_round(self):
        calls = {"IB-08": 0}

        def responder(body):
            user = next(m["content"] for m in body["messages"] if m["role"] == "user")
            rid = user.splitlines()[0].split(":")[0].replace("Requirement ", "").strip()
            resp = {"status": "pass", "summary": "ok", "violations": [], "rule_findings_review": [],
                    "spec_gaps": [], "need_files": [], "checked_files": [], "insufficient_data_reason": None}
            if rid == "IB-04":
                # оспариваем «вероятную» находку о ПД в открытом виде, указывая реальную строку
                resp["rule_findings_review"] = [{"id": "RF-1", "verdict": "dispute", "comment": "поля шифруются на уровне БД",
                                                 "counter_evidence": {"file": "portal/models.py", "line": 5}}]
            if rid == "IB-08":
                calls["IB-08"] += 1
                if calls["IB-08"] == 1:
                    resp["need_files"] = ["portal/storage.py", "nonexistent.py"]
                else:
                    assert "----- portal/storage.py" in user
                    resp["rule_findings_review"] = [{"id": "RF-1", "verdict": "confirm", "comment": "подтверждаю", "counter_evidence": None}]
            return json.dumps(resp, ensure_ascii=False)

        with FakeLLMServer("ok", responder=responder) as srv, tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(PROJECT_ROOT, out, "--provider", "deepseek", "--base-url", srv.base_url, "--model", "fake",
                             env_extra={"LLM_API_KEY": "k"})
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rep = load_report(out)
            self.assertEqual(len(srv.requests), 8)            # 7 требований + 1 дозапрос файлов
            self.assertEqual(calls["IB-08"], 2)
            st = rep["summary"]["requirements_status"]
            self.assertEqual(st["IB-04"], "pass")               # единственная «вероятная» находка оспорена
            disputed = [a for a in rep["additional_findings"] if a["category"] == "disputed-by-model"]
            self.assertEqual(len(disputed), 1)
            self.assertIn("portal/models.py:5", disputed[0]["description"])
            ib08 = [v for v in rep["violations"] if v["requirement_id"] == "IB-08"]
            self.assertEqual(ib08[0]["confidence"], "confirmed")
            self.assertEqual(ib08[0]["model_comment"], "подтверждаю")
            ib08_row = next(r for r in rep["summary"]["requirements"] if r["id"] == "IB-08")
            self.assertEqual(ib08_row["llm_rounds"], 2)


class ReportUnitTests(unittest.TestCase):
    def test_redaction(self):
        self.assertEqual(report_mod.redact("password = 'Training-2026!operator'"), "password = '***'")
        self.assertEqual(report_mod.redact("Authorization: Bearer abcdefghijklmnop"), "Authorization: Bearer ***")
        self.assertIn("sk-***", report_mod.redact("key sk-abcdefghijklmnop"))
        self.assertEqual(report_mod.redact("SESSION_COOKIE_SECURE = False"), "SESSION_COOKIE_SECURE = False")

    def test_redaction_keeps_code_expressions_but_masks_secrets(self):
        # прогон 36042637087: эти строки кода проверяемого проекта были испорчены в отчёте (`token = ***)`)
        for code in ("token = audit.actor.set(user.pk)",                                                # portal/views.py:188
                     "token = actor.set(request.user.pk if request.user.is_authenticated else 'anonymous')",  # portal/middleware.py:5
                     "token = None", "secret = settings.secret_key", "token = tokens[0]"):
            with self.subTest(code=code):
                self.assertEqual(report_mod.redact(code), code)
        # настоящие секреты по-прежнему маскируются — исправление не должно давать пропусков
        for secret, value in (('token = "sk-abc123"', "sk-abc123"), ("token = 'abc123xyz'", "abc123xyz"),
                              ("SECRET_KEY=django-insecure-abc123xyz", "django-insecure-abc123xyz"),
                              ("api_key=AbCdEf123456", "AbCdEf123456"), ("password: hunter2hunter", "hunter2hunter"),
                              ("token=eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9"),
                              ("header eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjF9.abc", "eyJ1aWQiOjF9")):
            with self.subTest(secret=secret):
                out = report_mod.redact(secret)
                self.assertNotIn(value, out)
                self.assertIn("***", out)


EXHAUSTED = {"content": None, "reasoning_content": "рассуждаю…", "finish_reason": "length",
             "reasoning_tokens": 8192, "completion_tokens": 8192}
PASS_JSON = json.dumps({"status": "pass", "summary": "ok", "violations": [], "rule_findings_review": [], "spec_gaps": [],
                        "need_files": [], "checked_files": [], "insufficient_data_reason": None}, ensure_ascii=False)


def _user_prompt(body):
    return next(m["content"] for m in body["messages"] if m["role"] == "user")


class ModelFailureRecoveryTests(unittest.TestCase):
    """Прогон 36037967344: по ИБ-04 модель вернула пустой ответ, требование молча оценено только правилами."""

    def _run(self, ib04_answers):
        calls = {"IB-04": 0}

        def responder(body):
            prompt = _user_prompt(body)
            if prompt.startswith("Requirement IB-04:"):
                calls["IB-04"] += 1
                return ib04_answers[min(calls["IB-04"], len(ib04_answers)) - 1]
            return PASS_JSON

        srv = FakeLLMServer("ok", responder=responder)
        with srv, tempfile.TemporaryDirectory() as td:
            out = Path(td)
            proc = run_agent(PROJECT_ROOT, out, "--provider", "deepseek", "--base-url", srv.base_url,
                             env_extra={"LLM_API_KEY": "k"})
            rep = load_report(out) if (out / "report.json").exists() else None
            md = (out / "report.md").read_text(encoding="utf-8") if (out / "report.md").exists() else ""
        self.md = md
        return proc, rep, srv, calls

    def test_exhausted_answer_is_retried_once_and_recovers(self):
        proc, rep, srv, calls = self._run([EXHAUSTED, PASS_JSON])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)   # нарушения правил по другим ИБ
        assert_report_shape(self, rep)
        self.assertEqual(calls["IB-04"], 2)
        self.assertEqual(len(srv.requests), 8)                              # 7 требований + 1 повтор
        ib04 = [r["body"] for r in srv.requests if _user_prompt(r["body"]).startswith("Requirement IB-04:")]
        retry_prompt = _user_prompt(ib04[1])
        self.assertIn("ТОЛЬКО один JSON-объект", retry_prompt)
        self.assertIn("finish_reason=length", retry_prompt)
        self.assertLess(len(retry_prompt), len(_user_prompt(ib04[0])))    # при обрезке по длине — меньше исходников
        # DeepSeek: режим рассуждений выключен в каждом запросе
        self.assertTrue(all(r["body"].get("thinking") == {"type": "disabled"} for r in srv.requests))
        self.assertFalse(any(l.startswith("ИБ-04:") for l in rep["limitations"]), rep["limitations"])
        per_call = rep["resources"]["llm"]["per_call"]
        self.assertEqual(len(per_call), 8)
        self.assertEqual(sum(1 for c in per_call if c["finish_reason"] == "length"), 1)
        self.assertTrue(any(c["reasoning_tokens"] == 8192 for c in per_call))
        ib04 = next(r for r in rep["summary"]["requirements"] if r["id"] == "IB-04")
        self.assertEqual(ib04["status"], "violation")              # находка правил сохраняется, модель её не сняла
        self.assertIsNone(ib04["insufficient_data_reason"])        # ответ модели после повтора пригоден
        self.assertIn("ИБ-04: violation: нарушений 1, отклонено 0, раундов 1; первый ответ модели непригоден, повтор успешен", proc.stdout)
        self.assertIn("нештатный ответ модели — finish_reason=length", proc.stdout)

    def test_persistent_empty_answer_is_recorded_in_limitations(self):
        proc, rep, srv, calls = self._run([EXHAUSTED, {"content": "", "finish_reason": "length", "completion_tokens": 4096}])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        assert_report_shape(self, rep)
        self.assertEqual(calls["IB-04"], 2)                                 # ровно один повтор, не больше
        ib04 = next(r for r in rep["summary"]["requirements"] if r["id"] == "IB-04")
        self.assertEqual(ib04["status"], "violation")                       # остаётся нарушение по правилам
        self.assertIsNone(ib04["insufficient_data_reason"])                 # без противоречивой пары
        self.assertIn("модель не дала пригодного ответа", ib04["analysis_warning"])
        self.assertIn("⚠️ анализ моделью: модель не дала пригодного ответа", self.md)
        lim = [l for l in rep["limitations"] if l.startswith("ИБ-04:")]
        self.assertEqual(len(lim), 1, rep["limitations"])
        self.assertIn("модель не дала пригодного ответа", lim[0])
        self.assertIn("finish_reason=length", lim[0])
        self.assertIn("только детерминированными правилами", lim[0])
        self.assertIn("::warning::модель не дала пригодного ответа по: ИБ-04", proc.stdout)
        self.assertIn("МОДЕЛЬ НЕ ДАЛА ПРИГОДНОГО ОТВЕТА", proc.stdout)


class DotenvTests(unittest.TestCase):
    def test_dotenv_fills_only_unset_vars(self):
        import main
        keys = ("IBT_NEW", "IBT_QUOTED", "IBT_PRESET")
        saved = {k: os.environ.get(k) for k in keys}
        try:
            for k in keys:
                os.environ.pop(k, None)
            os.environ["IBT_PRESET"] = "from-env"
            with tempfile.TemporaryDirectory() as tmp:
                env = Path(tmp) / ".env"
                env.write_text("# comment\nIBT_NEW=1\nIBT_QUOTED='a b'\nIBT_PRESET=from-file\nnot a pair\n", encoding="utf-8")
                main.load_dotenv(env)
            self.assertEqual(os.environ["IBT_NEW"], "1")
            self.assertEqual(os.environ["IBT_QUOTED"], "a b")
            self.assertEqual(os.environ["IBT_PRESET"], "from-env")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
