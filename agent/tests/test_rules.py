"""Тесты детерминированных правил (agent/rules.py).

Две опоры:
  1. реальный проект хакатона (этот репозиторий) — известные подозрительные
     места из .claude/03-test-project-map.md должны находиться;
  2. эталонная фикстура tests/fixtures/clean_project — ни одного нарушения
     (защита от ложных срабатываний на эталонной версии, ТЗ 5.2.1).
"""
import sys
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = AGENT_DIR.parent
CLEAN_ROOT = AGENT_DIR / "tests" / "fixtures" / "clean_project"
sys.path.insert(0, str(AGENT_DIR))

from indexer import Indexer  # noqa: E402
import rules  # noqa: E402
import analyzer  # noqa: E402


class RulesOnRealProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.out = rules.run_rules(cls.index, PROJECT_ROOT)
        cls.by_rule = {}
        for f in cls.out.findings:
            cls.by_rule.setdefault(f.rule_id, []).append(f)

    def _one(self, rule_id):
        self.assertIn(rule_id, self.by_rule, f"правило {rule_id} ничего не нашло; найдено: {sorted(self.by_rule)}")
        return self.by_rule[rule_id]

    def test_every_finding_is_grounded_in_a_real_line(self):
        for f in self.out.findings:
            path = PROJECT_ROOT / f.file
            self.assertTrue(path.is_file(), f)
            n = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
            self.assertTrue(1 <= f.line <= n, f)
            self.assertIn(f.severity, rules.SEVERITIES)
            self.assertTrue(f.justification and f.recommendation)

    def test_ib08_export_json_flagged_but_not_export_csv(self):
        fs = self._one("ib08.pii_export_without_role_check_or_audit")
        self.assertEqual({f.function for f in fs}, {"export_json"})
        self.assertEqual(fs[0].file, "portal/views.py")
        self.assertIn("аудит", fs[0].justification)

    def test_ib02_catalog_api_flagged_without_auth(self):
        fs = self._one("ib02.route_without_auth")
        self.assertEqual({f.function for f in fs}, {"catalog_api"})
        self.assertEqual(fs[0].severity, "critical")

    def test_ib02_token_expiry_not_enforced(self):
        fs = self._one("ib02.token_expiry_not_enforced")
        self.assertEqual(fs[0].function, "token_user")
        self.assertIn("signing.loads(", (PROJECT_ROOT / fs[0].file).read_text(encoding="utf-8").splitlines()[fs[0].line - 1])

    def test_ib01_manage_required_is_staff_grouped_with_routes(self):
        fs = self._one("ib01.admin_guard_checks_technical_flag")
        self.assertEqual(fs[0].file, "portal/access.py")
        patterns = {r["pattern"] for r in fs[0].related_locations}
        self.assertIn("manage/", patterns)
        self.assertIn("manage/users/<int:user_id>/role/", patterns)

    def test_ib01_queue_rename_api_only_login_required(self):
        fs = self._one("ib01.admin_route_without_role_check")
        self.assertEqual({f.function for f in fs}, {"queue_api"})

    def test_ib03_settings_flags_and_proxy_config(self):
        for rid in ("ib03.session_cookie_secure", "ib03.csrf_cookie_secure", "ib03.secure_ssl_redirect", "ib03.hsts_disabled"):
            self.assertEqual(self._one(rid)[0].file, "demodesk/config/settings.py")
        redirect = self._one("ib03.http_listener_without_redirect")[0]
        self.assertEqual((redirect.file, redirect.severity), ("proxy.json", "critical"))
        weak = self._one("ib03.weak_cipher_suites")[0]
        self.assertIn("AES128-SHA", weak.justification)
        self.assertNotIn("ECDHE-RSA-AES256-GCM-SHA384 (", weak.justification)

    def test_ib04_argon2_hasher_not_flagged_but_plaintext_pii_is(self):
        self.assertNotIn("ib04.weak_password_hasher", self.by_rule)
        self.assertNotIn("ib04.default_pbkdf2_hasher", self.by_rule)
        pii = self._one("ib04.pii_fields_stored_plaintext")[0]
        self.assertEqual((pii.file, pii.function), ("portal/models.py", "User"))
        self.assertEqual(pii.confidence, "likely")

    def test_ib05_acl_findings_and_no_false_positive_on_encrypted_writer(self):
        self.assertNotIn("ib05.log_written_unencrypted", self.by_rule)
        self._one("ib05.journal_key_readable_by_local_user")
        self._one("ib05.pending_journal_writable_by_local_user")

    def test_ib06_no_findings_all_references_present(self):
        self.assertFalse([f for f in self.out.findings if f.requirement_id == "IB-06"])

    def test_ib07_cross_cutting_findings(self):
        self._one("ib07.read_access_not_logged")
        self.assertEqual(self._one("ib07.bulk_update_bypasses_audit")[0].line, 81)
        self._one("ib07.no_dbms_event_log")
        self._one("ib07.access_denials_not_logged")

    def test_seed_update_goes_to_additional_not_violation(self):
        seeds = [f for f in self.out.findings if "seed_workload" in f.file]
        self.assertEqual(seeds, [])
        self.assertTrue(any("seed_workload" in a["location"]["file"] for a in self.out.additional))

    def test_ib07_read_routes_exclude_mutating_and_are_deduplicated(self):
        f = self._one("ib07.read_access_not_logged")[0]
        funcs = [r["function"] for r in f.related_locations]
        self.assertEqual(len(funcs), len(set(funcs)), funcs)
        for mutating in ("attachment_delete", "queue_api", "token_issue", "bulk_status"):
            self.assertNotIn(mutating, funcs)
        for read in ("ticket_list", "ticket_detail", "attachment", "ticket_api", "catalog_api"):
            self.assertIn(read, funcs)

    def test_spec_gaps_are_additional_not_violations(self):
        by_fn = {(a["location"]["file"], a["location"].get("function")): a for a in self.out.additional}
        for key in [("portal/views.py", "grant_queue"), ("portal/views.py", "change_role"),
                    ("portal/forms.py", "clean_attachment"), ("portal/access.py", "queues"),
                    ("portal/audit.py", "record"), ("portal/audit.py", "mutation")]:
            self.assertIn(key, by_fn, sorted(by_fn))
        for a in self.out.additional:
            self.assertIn(a.get("severity"), (None, "low", "medium", "high"))
            self.assertTrue(a["description"])

    def test_checked_has_every_requirement(self):
        self.assertEqual(set(self.out.checked), {f"IB-0{i}" for i in range(1, 9)})

    def test_cipher_evaluation(self):
        self.assertIsNone(rules.evaluate_cipher("ECDHE-RSA-AES128-GCM-SHA256"))
        self.assertIsNone(rules.evaluate_cipher("TLS_AES_256_GCM_SHA384"))
        self.assertIsNone(rules.evaluate_cipher("!aNULL"))
        self.assertIn("RSA", rules.evaluate_cipher("AES256-GCM-SHA384"))
        self.assertIn("CBC", rules.evaluate_cipher("ECDHE-RSA-AES128-SHA256"))
        self.assertIn("слаб", rules.evaluate_cipher("RC4-MD5"))
        self.assertIsNotNone(rules.evaluate_cipher("HIGH"))


class RulesOnCleanFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(CLEAN_ROOT).build()
        cls.out = rules.run_rules(cls.index, CLEAN_ROOT)

    def test_no_violations_on_reference_project(self):
        self.assertEqual([(f.rule_id, f.file, f.line) for f in self.out.findings], [])

    def test_no_limitations_and_ib06_pass(self):
        self.assertEqual(self.out.limitations, [])
        self.assertEqual(analyzer.analyze_ib06_deterministic(self.index).status, "pass")

    def test_index_found_generalized_modules(self):
        self.assertEqual(self.index["log_protection"]["acl_module"], "app/local_acl.py")
        self.assertEqual(self.index["log_protection"]["audit_module"], "app/audit.py")
        self.assertEqual(len(self.index["routes"]), 11)


if __name__ == "__main__":
    unittest.main()
