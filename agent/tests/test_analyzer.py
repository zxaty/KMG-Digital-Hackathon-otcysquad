"""Tests for agent/analyzer.py (module 3 - per-requirement LLM analysis).

No live LLM API is available in this environment (see analyzer.py's
module docstring), so every test here uses MockLLMClient with a
scripted response. What IS proven for real: the evidence bundle is
built from the actual project's real index.json (via Indexer, the same
module-2 code already verified in agent/tests/test_indexer.py), and the
validation/enforcement pipeline (location allowlist, evidence backfill
from real source, severity clamping, status reconciliation) runs
against that real data, not a synthetic fixture. What remains unproven:
whether a real model actually produces output this pipeline can parse -
that requires credentials this environment does not have.

Run with:
    python3 -m unittest discover -s agent/tests -v
"""
import json
import sys
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from indexer import Indexer  # noqa: E402
import analyzer  # noqa: E402


class AnalyzerAgainstRealIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.evidence = analyzer.build_evidence_ib07(cls.index)
        cls.evidence_by_req = {rid: builder(cls.index) for rid, builder in analyzer.EVIDENCE_BUILDERS.items()}

    # ---------- evidence bundling ----------

    def test_ib07_evidence_bundle_has_the_real_bulk_status_candidate(self):
        candidates = self.evidence["bulk_orm_bypass_candidates"]
        matches = [c for c in candidates if c["file"] == "portal/views.py" and c["line"] == 81]
        self.assertEqual(len(matches), 1)

    def test_ib07_evidence_excludes_non_queryset_update_calls(self):
        # 16 total bulk_orm_calls in the real project, only 3 look like real
        # querysets (see agent/tests/test_indexer.py) - the bundle must not
        # pass the other 13 through as noise.
        self.assertEqual(len(self.evidence["bulk_orm_bypass_candidates"]), 3)

    def test_ib07_evidence_reports_zero_uncovered_models(self):
        self.assertEqual(self.evidence["model_count_uncovered"], 0)

    def test_known_locations_extracted_from_evidence_include_the_real_candidate(self):
        locations = analyzer.collect_known_locations(self.evidence)
        self.assertIn(("portal/views.py", 81), locations)

    # ---------- happy path: a grounded violation is kept and gets a real snippet ----------

    def test_grounded_violation_is_kept_with_real_evidence_snippet(self):
        scripted = json.dumps({
            "status": "violation",
            "summary": "bulk_status bypasses the audit trail via QuerySet.update().",
            "violations": [{
                "location": {"file": "portal/views.py", "line": 81, "function": "bulk_status"},
                "justification": "QuerySet.update() does not fire post_save, so this mutation is never audited.",
                "severity": "high",
                "recommendation": "Iterate and call .save() per instance, or add an explicit audit.record() call.",
            }],
            "insufficient_data_reason": None,
        })
        client = analyzer.MockLLMClient(scripted_response=scripted)
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)

        self.assertEqual(result.status, "violation")
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(len(result.rejected), 0)
        v = result.violations[0]
        self.assertEqual(v.severity, "high")
        # the snippet must be the REAL line from the real file, not model prose
        self.assertIn("selected.update(status=status)", v.evidence_snippet)
        self.assertEqual(result.requirement_text, analyzer.IB_REQUIREMENTS["IB-07"])

    def test_evidence_snippet_is_byte_exact_against_the_real_file(self):
        # Independently re-read the real file in the test itself (not via
        # analyzer.extract_snippet) so this doesn't just check the function
        # against itself - it checks the pipeline's output against a second,
        # separate read of the actual file on disk.
        real_line = (PROJECT_ROOT / "portal" / "views.py").read_text(encoding="utf-8").splitlines()[81 - 1]
        scripted = json.dumps({
            "status": "violation",
            "summary": "x",
            "violations": [{
                "location": {"file": "portal/views.py", "line": 81, "function": "bulk_status"},
                "justification": "x",
                "severity": "high",
                "recommendation": "x",
            }],
            "insufficient_data_reason": None,
        })
        client = analyzer.MockLLMClient(scripted_response=scripted)
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(result.violations[0].evidence_snippet, real_line)

    # ---------- hallucinated location is rejected, not silently kept ----------

    def test_hallucinated_location_is_rejected(self):
        scripted = json.dumps({
            "status": "violation",
            "summary": "made up",
            "violations": [{
                "location": {"file": "portal/views.py", "line": 9999, "function": "nonexistent"},
                "justification": "this location was never in the evidence bundle",
                "severity": "high",
                "recommendation": "n/a",
            }],
            "insufficient_data_reason": None,
        })
        client = analyzer.MockLLMClient(scripted_response=scripted)
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)

        self.assertEqual(len(result.violations), 0)
        self.assertEqual(len(result.rejected), 1)
        self.assertIn("hallucinated", result.rejected[0].reason)
        # a claimed "violation" status with zero grounded findings must not
        # collapse to a false "pass" - it must be visibly insufficient_data
        self.assertEqual(result.status, "insufficient_data")
        self.assertIsNotNone(result.insufficient_data_reason)

    # ---------- claimed "violation" with an empty list must not become a silent "pass" ----------

    def test_claimed_violation_with_empty_violations_list_is_insufficient_data(self):
        # Distinct from test_hallucinated_location_is_rejected: there, the
        # model listed an item that got rejected (rejected is non-empty).
        # Here it lists nothing at all (rejected is also empty) - the
        # reconciliation logic must not fall through to "pass" in this case.
        scripted = json.dumps({
            "status": "violation",
            "summary": "claims a violation but lists none",
            "violations": [],
            "insufficient_data_reason": None,
        })
        client = analyzer.MockLLMClient(scripted_response=scripted)
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)

        self.assertEqual(result.violations, [])
        self.assertEqual(result.rejected, [])
        self.assertEqual(result.status, "insufficient_data")
        self.assertIsNotNone(result.insufficient_data_reason)
        self.assertIn("empty", result.insufficient_data_reason)

    # ---------- missing location is rejected ----------

    def test_missing_location_is_rejected(self):
        scripted = json.dumps({
            "status": "violation",
            "summary": "vague claim with no location",
            "violations": [{
                "location": {"file": None, "line": None},
                "justification": "something is wrong somewhere",
                "severity": "high",
                "recommendation": "n/a",
            }],
            "insufficient_data_reason": None,
        })
        client = analyzer.MockLLMClient(scripted_response=scripted)
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)

        self.assertEqual(len(result.violations), 0)
        self.assertEqual(len(result.rejected), 1)
        self.assertIn("missing or malformed location", result.rejected[0].reason)
        self.assertEqual(result.status, "insufficient_data")

    # ---------- clean pass ----------

    def test_pass_status_with_no_violations(self):
        scripted = json.dumps({
            "status": "pass",
            "summary": "All models covered by mutation signals; no ungrounded bypass found.",
            "violations": [],
            "insufficient_data_reason": None,
        })
        client = analyzer.MockLLMClient(scripted_response=scripted)
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.violations, [])

    # ---------- malformed JSON from the model ----------

    def test_malformed_json_becomes_insufficient_data_not_a_crash(self):
        client = analyzer.MockLLMClient(scripted_response="not json at all { broken")
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)
        self.assertEqual(result.status, "insufficient_data")
        self.assertIsNotNone(result.parse_error)

    # ---------- bad severity value gets clamped, finding still kept ----------

    def test_invalid_severity_is_clamped_not_dropped(self):
        scripted = json.dumps({
            "status": "violation",
            "summary": "x",
            "violations": [{
                "location": {"file": "portal/views.py", "line": 81, "function": "bulk_status"},
                "justification": "x",
                "severity": "SUPER_CRITICAL_OMG",  # not one of the 4 allowed values
                "recommendation": "x",
            }],
            "insufficient_data_reason": None,
        })
        client = analyzer.MockLLMClient(scripted_response=scripted)
        result = analyzer.analyze_requirement("IB-07", self.index, client, PROJECT_ROOT)
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(result.violations[0].severity, analyzer.DEFAULT_SEVERITY)

    # ---------- unknown requirement id fails loudly, not silently ----------

    def test_unknown_requirement_id_raises_value_error(self):
        client = analyzer.MockLLMClient(scripted_response="{}")
        with self.assertRaises(ValueError):
            analyzer.analyze_requirement("IB-99", self.index, client, PROJECT_ROOT)

    def test_all_eight_requirements_have_an_evidence_builder(self):
        self.assertEqual(set(analyzer.EVIDENCE_BUILDERS.keys()), set(analyzer.IB_REQUIREMENTS.keys()))
        self.assertEqual(set(analyzer.IB_REQUIREMENTS.keys()),
                          {f"IB-{n:02d}" for n in range(1, 9)})


class Ib06DeterministicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()

    def test_real_project_is_pass_with_no_violations(self):
        # This project's README already has all 6 references (see
        # test_indexer.py's regulatory-references test) - so the real
        # project can only exercise the "pass" branch. The "violation"
        # branch is tested below against synthetic data.
        result = analyzer.analyze_ib06_deterministic(self.index)
        self.assertEqual(result.status, "pass")
        self.assertEqual(result.violations, [])
        self.assertEqual(result.requirement_text, analyzer.IB_REQUIREMENTS["IB-06"])

    def test_no_llm_call_needed_deterministic_result_is_reproducible(self):
        a = analyzer.analyze_ib06_deterministic(self.index)
        b = analyzer.analyze_ib06_deterministic(self.index)
        self.assertEqual(a.status, b.status)
        self.assertEqual(len(a.violations), len(b.violations))

    def test_missing_reference_with_evidence_produces_grounded_violation(self):
        fake_index = {
            "regulatory_references": {
                "searched_files": ["README.md"],
                "all_six_present": False,
                "reference_found": {"law_cybersecurity_418-V_2015-11-24": False, "gost_rk_1073-2007": True},
                "reference_evidence": {
                    "law_cybersecurity_418-V_2015-11-24": [],
                    "gost_rk_1073-2007": [{"file": "README.md", "line": 127, "text": "6. ..."}],
                },
            }
        }
        result = analyzer.analyze_ib06_deterministic(fake_index)
        self.assertEqual(result.status, "violation")
        self.assertEqual(len(result.violations), 1)
        v = result.violations[0]
        self.assertIn("418-V", v.justification)
        # no evidence for the missing one -> honest degradation, no fabricated line
        self.assertEqual(v.location["file"], "README.md")  # first searched_files entry
        self.assertIsNone(v.location["line"])

    def test_missing_reference_with_no_searched_files_degrades_to_null_file(self):
        fake_index = {
            "regulatory_references": {
                "searched_files": [],
                "all_six_present": False,
                "reference_found": {"gost_rk_1073-2007": False},
                "reference_evidence": {"gost_rk_1073-2007": []},
            }
        }
        result = analyzer.analyze_ib06_deterministic(fake_index)
        self.assertEqual(len(result.violations), 1)
        self.assertIsNone(result.violations[0].location["file"])
        self.assertIsNone(result.violations[0].location["line"])


class Ib01EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.evidence = analyzer.build_evidence_ib01(cls.index)

    def test_all_routes_present_not_prefiltered(self):
        self.assertEqual(len(self.evidence["routes"]), 22)

    def test_manage_routes_show_manage_required_not_admin_required(self):
        manage_routes = [r for r in self.evidence["routes"] if r["view_function"] in
                          ("manage", "change_role", "grant_queue", "reset_password")]
        self.assertEqual(len(manage_routes), 4)
        for r in manage_routes:
            self.assertIn("portal.access.manage_required", r["decorators"])
            self.assertNotIn("portal.access.admin_required", r["decorators"])

    def test_guard_definitions_included_for_model_to_judge_is_staff_vs_role(self):
        gd = self.evidence["guard_definitions"]
        self.assertIn("is_staff", gd["portal.access.manage_required"]["source"])
        self.assertIn("role == 'administrator'", gd["portal.access.administrator"]["source"])

    def test_admin_panel_not_in_installed_apps(self):
        self.assertNotIn("django.contrib.admin", self.evidence["installed_apps"])


class Ib02EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.evidence = analyzer.build_evidence_ib02(cls.index)

    def test_catalog_api_route_present_with_no_guard_visible_to_the_model(self):
        r = next(r for r in self.evidence["routes"] if r["view_function"] == "catalog_api")
        self.assertEqual(r["url_level_wrappers"], [])
        self.assertNotIn("django.contrib.auth.decorators.login_required", r["decorators"])

    def test_token_lifecycle_present_with_the_real_expiry_gap(self):
        tl = self.evidence["token_lifecycle"]
        issuer = next(i for i in tl["issuers"] if i["function"] == "token_issue")
        validator = next(v for v in tl["validators"] if v["function"] == "token_user")
        self.assertTrue(issuer["embeds_exp_claim"])
        self.assertFalse(validator["checks_exp_claim"])

    def test_authentication_middleware_present(self):
        self.assertIn("django.contrib.auth.middleware.AuthenticationMiddleware", self.evidence["middleware"])


class Ib03EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.evidence = analyzer.build_evidence_ib03(cls.index)

    def test_relevant_settings_show_transport_flags_disabled(self):
        s = self.evidence["relevant_settings"]
        self.assertEqual(s["SESSION_COOKIE_SECURE"]["value"], False)
        self.assertEqual(s["SECURE_SSL_REDIRECT"]["value"], False)
        self.assertEqual(s["SECURE_HSTS_SECONDS"]["value"], 0)

    def test_proxy_json_present_in_auxiliary_configs(self):
        proxy = self.evidence["auxiliary_configs"].get("proxy.json")
        self.assertEqual(proxy["minimum_tls"], "TLSv1_2")
        self.assertFalse(proxy["http_redirect"])


class Ib04EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.evidence = analyzer.build_evidence_ib04(cls.index)

    def test_password_hasher_present(self):
        self.assertEqual(self.evidence["password_hashers"]["value"], ["portal.hashers.PasswordHasher"])

    def test_pii_flagged_fields_include_user_model_fields_only(self):
        user_entry = next(m for m in self.evidence["pii_flagged_model_fields"]
                           if m["class_name"] == "User" and m["app_dir"] == "portal")
        names = {f["name"] for f in user_entry["pii_fields"]}
        self.assertTrue({"email", "first_name", "last_name"} <= names)
        # every field in every model bucket must actually be PII-flagged -
        # this builder must not silently let non-PII fields through
        for m in self.evidence["pii_flagged_model_fields"]:
            for f in m["pii_fields"]:
                self.assertTrue(f["pii_name_hint"])

    def test_no_password_bypass_writes(self):
        self.assertEqual(self.evidence["password_bypass_writes"], [])


class Ib05EvidenceTests(unittest.TestCase):
    def test_log_protection_passthrough_matches_index(self):
        index = Indexer(PROJECT_ROOT).build()
        evidence = analyzer.build_evidence_ib05(index)
        self.assertEqual(evidence["log_protection"], index["log_protection"])
        self.assertEqual(len(evidence["log_protection"]["local_acl_configure_calls"]), 5)


class Ib06EvidenceTests(unittest.TestCase):
    def test_regulatory_references_all_present(self):
        index = Indexer(PROJECT_ROOT).build()
        evidence = analyzer.build_evidence_ib06(index)
        self.assertTrue(evidence["regulatory_references"]["all_six_present"])


class Ib08EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()
        cls.evidence = analyzer.build_evidence_ib08(cls.index)

    def test_exactly_the_two_export_routes_are_selected(self):
        view_functions = sorted(r["view_function"] for r in self.evidence["export_like_routes"])
        self.assertEqual(view_functions, ["export_csv", "export_json"])

    def test_export_csv_vs_export_json_asymmetry_visible_in_evidence(self):
        by_view = {r["view_function"]: r for r in self.evidence["export_like_routes"]}
        self.assertIn("portal.access.admin_required", by_view["export_csv"]["decorators"])
        self.assertTrue(any(a["name"] == "portal.audit.record" for a in by_view["export_csv"]["audit_calls"]))
        self.assertNotIn("portal.access.admin_required", by_view["export_json"]["decorators"])
        self.assertEqual(by_view["export_json"]["audit_calls"], [])


if __name__ == "__main__":
    unittest.main()
