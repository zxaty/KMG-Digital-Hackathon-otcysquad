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
    cmd = [sys.executable, str(AGENT_DIR / "main.py"), "--project-root", str(project_root),
           "--out-json", str(out_dir / "report.json"), "--out-md", str(out_dir / "report.md"), *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
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
            proc = run_agent(PROJECT_ROOT, out, "--provider", "custom", "--base-url", srv.base_url, "--model", "fake",
                             env_extra={"LLM_API_KEY": "k"})
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            rep = load_report(out)
            assert_report_shape(self, rep)
            self.assertEqual(len(srv.requests), 7)  # IB-06 без модели
            self.assertEqual(rep["meta"]["model"], "custom/fake")
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
            proc = run_agent(PROJECT_ROOT, out, "--provider", "custom", "--base-url", "http://127.0.0.1:9/v1",
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
            proc = run_agent(PROJECT_ROOT, out, "--provider", "custom", "--base-url", srv.base_url, "--model", "fake",
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
            proc = run_agent(CLEAN_ROOT, out, "--provider", "custom", "--base-url", srv.base_url, "--model", "fake",
                             env_extra={"LLM_API_KEY": "k"})
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            rep = load_report(out)
            statuses = rep["summary"]["requirements_status"]
            self.assertEqual(statuses["IB-06"], "pass")
            self.assertEqual({v for k, v in statuses.items() if k != "IB-06"}, {"insufficient_data"})
            self.assertIn("::warning::", proc.stdout)
            proc2 = run_agent(CLEAN_ROOT, out, "--provider", "custom", "--base-url", srv.base_url, "--model", "fake",
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
            proc = run_agent(PROJECT_ROOT, out, "--provider", "custom", "--base-url", srv.base_url, "--model", "fake",
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
