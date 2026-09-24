"""Regression tests for agent/indexer.py (module 2 - context collection).

These lock in facts that were already manually verified against the real
target project (this repo doubles as both our solution and the IB-check
target) during interactive development: route/model counts, the
is_staff-vs-role distinction on /manage/*, catalog_api's total lack of a
guard, the export_csv/export_json asymmetry, the token expiry gap, signal
coverage, etc. If any of these break, either the indexer regressed or the
target project's own code changed under it - both are worth finding out
immediately from a single command, not by re-running ad-hoc inspection
scripts by hand.

Run with:
    python3 -m unittest discover -s agent/tests -v

Uses stdlib unittest, not pytest: pytest is not installed in this
environment and this sandbox's Python is externally-managed (installing
it would need --break-system-packages), so unittest was used instead to
avoid adding a dependency that might not be reliably available in CI.
"""
import sys
import tempfile
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from indexer import Indexer  # noqa: E402


class IndexerAgainstRealProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()

    def routes_for(self, view_function):
        matches = [r for r in self.index["routes"] if r.get("view_function") == view_function]
        self.assertTrue(matches, f"no route found for view_function={view_function!r}")
        return matches

    def route_for(self, view_function, pattern):
        matches = [r for r in self.routes_for(view_function) if r["pattern"] == pattern]
        self.assertEqual(len(matches), 1, f"expected exactly one route for {view_function!r}/{pattern!r}, got {len(matches)}")
        return matches[0]

    # ---------- structural sanity ----------

    def test_index_has_all_expected_top_level_keys(self):
        expected = {
            "meta", "settings", "routes", "guard_definitions", "models",
            "bulk_orm_calls", "signal_wiring", "model_audit_coverage",
            "log_protection", "token_lifecycle", "login_throttling",
            "password_validators", "auxiliary_configs", "password_bypass_writes",
            "regulatory_references", "notes", "inventory",
        }
        self.assertEqual(expected, set(self.index.keys()))

    def test_route_count(self):
        self.assertEqual(len(self.index["routes"]), 22)

    def test_model_count(self):
        self.assertEqual(len(self.index["models"]), 22)

    def test_build_is_stable_across_reruns(self):
        second = Indexer(PROJECT_ROOT).build()
        self.assertEqual(len(second["routes"]), len(self.index["routes"]))
        self.assertEqual(len(second["models"]), len(self.index["models"]))

    def test_checker_and_ci_directories_are_excluded_from_project_scan(self):
        """The checker must not mistake its own code/workflow for target evidence."""
        excluded = {"agent", ".github", ".claude"}
        scanned = list(Indexer(PROJECT_ROOT).iter_project_py_files())
        self.assertTrue(scanned)
        for path in scanned:
            relative_parts = set(path.relative_to(PROJECT_ROOT).parts)
            self.assertTrue(
                excluded.isdisjoint(relative_parts),
                f"self-scan regression: {path} came from an excluded directory",
            )

    def test_no_unexpected_notes(self):
        known_note_substrings = (
            "could not locate module `django.contrib.auth.views`",
            "not parsed (binary format)",
        )
        for note in self.index["notes"]:
            self.assertTrue(
                any(s in note["message"] for s in known_note_substrings),
                f"unexpected/new note, investigate before trusting the rest of the index: {note}",
            )

    # ---------- IB-01: admin access control ----------

    def test_manage_routes_use_manage_required_not_admin_required(self):
        for view in ("manage", "change_role", "grant_queue", "reset_password"):
            for r in self.routes_for(view):
                self.assertIn("portal.access.manage_required", r["decorators"])
                self.assertNotIn("portal.access.admin_required", r["decorators"])

    def test_guard_definitions_show_the_is_staff_vs_role_distinction(self):
        gd = self.index["guard_definitions"]
        for name in ("portal.access.manage_required", "portal.access.admin_required", "portal.access.administrator"):
            self.assertIn(name, gd, f"{name} was not resolved into guard_definitions")
        self.assertIn("is_staff", gd["portal.access.manage_required"]["source"])
        self.assertIn("administrator(request.user)", gd["portal.access.admin_required"]["source"])
        self.assertIn("role == 'administrator'", gd["portal.access.administrator"]["source"])

    def test_admin_panel_not_installed(self):
        apps = self.index["settings"]["INSTALLED_APPS"]["value"]
        self.assertNotIn("django.contrib.admin", apps)

    # ---------- IB-02: server-side session/token validation ----------

    def test_catalog_api_has_no_guard_at_all(self):
        r = self.route_for("catalog_api", "api/catalog/tickets/")
        self.assertEqual(r["url_level_wrappers"], [])
        self.assertNotIn("django.contrib.auth.decorators.login_required", r["decorators"])
        self.assertEqual(r["body_guard_calls"], [])

    def test_token_issuer_embeds_exp_but_validator_never_checks_it(self):
        tl = self.index["token_lifecycle"]
        issuer = next(i for i in tl["issuers"] if i["function"] == "token_issue")
        validator = next(v for v in tl["validators"] if v["function"] == "token_user")
        self.assertTrue(issuer["embeds_exp_claim"])
        self.assertFalse(validator["checks_exp_claim"])

    def test_no_token_revocation_on_role_or_password_change(self):
        entries = self.index["token_lifecycle"]["role_or_password_change_functions"]
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual(entry["revocation_related_calls"], [],
                              f"{entry['function']} unexpectedly references revocation-related state")

    # ---------- IB-03: transport security ----------

    def test_transport_security_flags_are_disabled(self):
        s = self.index["settings"]
        for key in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SECURE_SSL_REDIRECT"):
            self.assertEqual(s[key]["value"], False, f"{key} expected False")
        self.assertEqual(s["SECURE_HSTS_SECONDS"]["value"], 0)

    def test_proxy_json_present_with_tls_config(self):
        proxy = self.index["auxiliary_configs"].get("proxy.json")
        self.assertIsNotNone(proxy, "proxy.json was not picked up by index_auxiliary_configs")
        self.assertEqual(proxy["minimum_tls"], "TLSv1_2")
        self.assertFalse(proxy["http_redirect"])

    # ---------- IB-04: crypto protection of PII at rest ----------

    def test_password_hasher_is_the_project_argon2_hasher(self):
        hashers = self.index["settings"]["PASSWORD_HASHERS"]["value"]
        self.assertEqual(hashers, ["portal.hashers.PasswordHasher"])

    def test_no_password_bypass_writes_found(self):
        self.assertEqual(self.index["password_bypass_writes"], [])

    def test_pii_fields_flagged_on_user_model(self):
        user_model = next(m for m in self.index["models"] if m["class_name"] == "User" and m["app_dir"] == "portal")
        flagged = {f["name"] for f in user_model["fields"] if f["pii_name_hint"]}
        self.assertTrue({"email", "first_name", "last_name"} <= flagged)

    # ---------- IB-05: local log protection ----------

    def test_local_acl_configures_five_paths_with_expected_access_levels(self):
        calls = self.index["log_protection"]["local_acl_configure_calls"]
        self.assertEqual(len(calls), 5)
        access_by_path = {c["path_expr"]: c["access"] for c in calls}
        self.assertEqual(access_by_path["runtime / 'keys'"], "none")
        self.assertEqual(access_by_path["runtime / 'journal' / 'pending'"], "modify")
        self.assertEqual(access_by_path["runtime / 'journal' / 'received'"], "none")

    def test_audit_record_uses_aead_and_atomic_write(self):
        fn = next(f for f in self.index["log_protection"]["audit_functions"] if f["function"] == "record")
        self.assertTrue(fn["uses_aead"])
        self.assertTrue(fn["atomic_write_pattern"])

    # ---------- IB-06: regulatory references ----------

    def test_all_six_regulatory_references_present_with_line_evidence(self):
        rr = self.index["regulatory_references"]
        self.assertTrue(rr["all_six_present"], rr["reference_found"])
        self.assertIn("README.md", rr["searched_files"])
        # every reference must have at least one piece of file+line evidence,
        # not just a bare boolean - and it must land in README's dedicated
        # "regulatory sources" section (lines 122-127), not a coincidental
        # substring match elsewhere in the project
        for key, hits in rr["reference_evidence"].items():
            self.assertTrue(hits, f"{key} has no line-level evidence")
            for h in hits:
                self.assertEqual(h["file"], "README.md")
                self.assertTrue(122 <= h["line"] <= 127, f"{key} matched outside the expected README lines: {h}")

    # ---------- IB-07: unified audit log coverage ----------

    def test_all_models_covered_by_mutation_signals(self):
        uncovered = [m for m in self.index["model_audit_coverage"] if not m["covered_by_post_save_post_delete_signals"]]
        self.assertEqual(uncovered, [])

    def test_bulk_status_bypasses_audit_signals(self):
        hits = [h for h in self.index["bulk_orm_calls"] if h["file"] == "portal/views.py" and h["line"] == 81]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]["looks_like_queryset"])

    def test_signal_handler_filter_covers_both_local_apps(self):
        filt = self.index["signal_wiring"]["handler_app_label_filters"]["portal.audit.mutation"]
        self.assertEqual(set(filt["allowed_app_labels"]), {"helpdesk", "portal"})

    # ---------- IB-08: PII export control ----------

    def test_export_csv_has_role_check_and_audit_call(self):
        r = self.route_for("export_csv", "exports/people.csv")
        self.assertIn("portal.access.admin_required", r["decorators"])
        self.assertTrue(any(a["name"] == "portal.audit.record" for a in r["audit_calls"]))

    def test_export_json_has_neither_role_check_nor_audit_call(self):
        r = self.route_for("export_json", "exports/people.json")
        self.assertNotIn("portal.access.admin_required", r["decorators"])
        self.assertEqual(r["audit_calls"], [])

    # ---------- Tech-Spec-adjacent (not one of the 8 IB requirements, still worth locking in) ----------

    def test_no_login_throttling_mechanism(self):
        self.assertFalse(self.index["login_throttling"]["throttling_mechanism_found"])

    def test_password_validators_cover_length_only(self):
        pv = self.index["password_validators"]
        self.assertTrue(pv["covers_minimum_length"])
        self.assertFalse(pv["covers_common_password_rejection"])
        self.assertFalse(pv["covers_all_numeric_rejection"])
        self.assertFalse(pv["covers_password_reuse_block"])


class AgentOwnFilesExcludedTests(unittest.TestCase):
    """The agent's own CI workflow must not be inventoried as target input,
    while the target project's own workflows must be."""

    def test_own_workflow_skipped_target_workflow_kept_as_ci(self):
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp) / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "ib-check.yml").write_text("name: ib-security-check\n", encoding="utf-8")
            (wf / "deploy.yml").write_text("name: deploy\n", encoding="utf-8")
            files = {f["path"]: f for f in Indexer(Path(tmp)).index_inventory()["files"]}
        self.assertNotIn(".github/workflows/ib-check.yml", files)
        self.assertIn(".github/workflows/deploy.yml", files)
        self.assertEqual(files[".github/workflows/deploy.yml"]["category"], "ci")


if __name__ == "__main__":
    unittest.main()
