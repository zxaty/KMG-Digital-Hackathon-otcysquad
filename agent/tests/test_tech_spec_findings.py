"""Tests for agent/tech_spec_findings.py against the real project's index.

No LLM involved anywhere in this module or its tests - these three
checks are fully resolved by module 2 (agent/indexer.py) alone, so
correctness here is entirely about reading index.json's already-computed
fields correctly and honestly resolving real (file, line) locations, not
about model behavior.

Run with:
    python3 -m unittest discover -s agent/tests -v
"""
import sys
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from indexer import Indexer  # noqa: E402
import tech_spec_findings as tsf  # noqa: E402


class TechSpecFindingsAgainstRealProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.findings = tsf.assemble_tech_spec_findings(cls.index)

    # ---------- overall shape ----------

    def test_four_findings_from_three_checks(self):
        # 1 throttling + 1 combined password-validator + 2 token-revocation
        # (change_role, reset_password) = 4 real, distinct locations.
        self.assertEqual(len(self.findings), 4)

    def test_every_finding_has_the_required_schema_fields(self):
        for f in self.findings:
            self.assertIn("category", f)
            self.assertIn("description", f)
            self.assertIn("location", f)
            self.assertIn("file", f["location"])
            self.assertIn("line", f["location"])
            self.assertIsInstance(f["description"], str)
            self.assertTrue(f["description"])

    def test_all_findings_use_session_auth_detail_category(self):
        for f in self.findings:
            self.assertEqual(f["category"], "session-auth-detail")

    # ---------- check 1: login throttling ----------

    def test_login_throttling_finding_present_with_real_settings_location(self):
        findings = tsf.find_missing_login_throttling(self.index)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["location"]["file"], "demodesk/config/settings.py")
        self.assertEqual(f["location"]["line"], self.index["settings"]["INSTALLED_APPS"]["line"])
        self.assertIn("4.4.6", f["description"])
        self.assertIn("axes", f["description"].lower())

    def test_login_throttling_finding_absent_if_mechanism_found(self):
        fake_index = {"login_throttling": {"throttling_mechanism_found": True}}
        self.assertEqual(tsf.find_missing_login_throttling(fake_index), [])

    # ---------- check 2: password validators ----------

    def test_password_validator_finding_present_and_combined(self):
        findings = tsf.find_incomplete_password_validators(self.index)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["location"]["file"], "demodesk/config/settings.py")
        self.assertEqual(f["location"]["line"], self.index["settings"]["AUTH_PASSWORD_VALIDATORS"]["line"])
        self.assertIn("4.4.8", f["description"])
        # all three missing behaviors named in the one combined description
        self.assertIn("common", f["description"].lower())
        self.assertIn("numeric", f["description"].lower())
        self.assertIn("reuse", f["description"].lower())

    def test_password_validator_finding_absent_when_all_covered(self):
        fake_index = {"password_validators": {
            "covers_common_password_rejection": True,
            "covers_all_numeric_rejection": True,
            "covers_password_reuse_block": True,
            "configured_validators": ["x"],
        }}
        self.assertEqual(tsf.find_incomplete_password_validators(fake_index), [])

    def test_password_validator_finding_lists_only_actually_missing_behaviors(self):
        fake_index = {"password_validators": {
            "covers_common_password_rejection": True,   # covered - should NOT be named
            "covers_all_numeric_rejection": False,       # missing - SHOULD be named
            "covers_password_reuse_block": False,        # missing - SHOULD be named
            "configured_validators": ["a.b.MinimumLengthValidator", "a.b.CommonPasswordValidator"],
        }}
        findings = tsf.find_incomplete_password_validators(fake_index)
        self.assertEqual(len(findings), 1)
        desc = findings[0]["description"].lower()
        self.assertNotIn("common/well-known", desc)
        self.assertIn("numeric", desc)
        self.assertIn("reuse", desc)

    # ---------- check 3: token revocation ----------

    def test_token_revocation_findings_present_for_both_real_functions(self):
        findings = tsf.find_missing_token_revocation(self.index)
        functions = sorted(f["description"] for f in findings)
        self.assertEqual(len(findings), 2)
        by_location = {(f["location"]["file"], f["location"]["line"]) for f in findings}
        # locations must be the REAL, distinct lines from token_lifecycle,
        # not a shared/fabricated one
        expected = {
            (e["file"], e["line"])
            for e in self.index["token_lifecycle"]["role_or_password_change_functions"]
            if not e["revocation_related_calls"]
        }
        self.assertEqual(by_location, expected)
        self.assertEqual(len(by_location), 2)  # change_role and reset_password are distinct lines

    def test_token_revocation_finding_names_the_actual_function(self):
        findings = tsf.find_missing_token_revocation(self.index)
        function_names_mentioned = {f["description"] for f in findings}
        self.assertTrue(any("change_role" in d for d in function_names_mentioned))
        self.assertTrue(any("reset_password" in d for d in function_names_mentioned))

    def test_token_revocation_finding_skipped_when_revocation_calls_present(self):
        fake_index = {"token_lifecycle": {"role_or_password_change_functions": [
            {"function": "reset_password", "file": "x.py", "line": 1, "revocation_related_calls": ["session.flush"]},
        ]}}
        self.assertEqual(tsf.find_missing_token_revocation(fake_index), [])

    # ---------- location honesty: never fabricate a file when unresolvable ----------

    def test_settings_location_degrades_honestly_when_file_cannot_be_resolved(self):
        fake_index = {
            "meta": {"root": "/nonexistent/root", "search_roots": ["/nonexistent/root"], "settings_module": "not.a.real.module"},
            "settings": {"INSTALLED_APPS": {"line": 5}},
        }
        loc = tsf._settings_location(fake_index, "INSTALLED_APPS")
        self.assertEqual(loc["file"], "not.a.real.module")
        self.assertIsNone(loc["line"])


if __name__ == "__main__":
    unittest.main()
