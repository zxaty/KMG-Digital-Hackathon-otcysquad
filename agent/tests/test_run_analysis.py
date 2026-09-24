"""Tests for agent/run_analysis.py - the module-3 orchestrator that
routes all 8 IB requirements (7 to the LLM path, IB-06 to the
deterministic path) and merges in the Tech-Spec additional_findings.

Uses a uniform-"pass" mock response for the 7 LLM-backed requirements:
per-requirement correctness (grounded violations, rejection paths,
evidence backfill) is already exhaustively covered in test_analyzer.py.
What this file proves is ORCHESTRATION correctness - the right analyzer
function gets called for the right requirement, IB-06 genuinely never
touches the LLM client, and the merged RunResult has the shape module 4
will need.

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
import tech_spec_findings  # noqa: E402
import run_analysis  # noqa: E402


class RecordingLLMClient:
    """Like MockLLMClient, but records every user_prompt it was called
    with, so a test can mechanically prove WHICH requirements actually
    reached the model - not just infer it from the returned status."""

    def __init__(self, response: str):
        self.response = response
        self.calls: list[str] = []

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.calls.append(user_prompt)
        return self.response


GENERIC_PASS = json.dumps({
    "status": "pass",
    "summary": "generic mock pass",
    "violations": [],
    "insufficient_data_reason": None,
})


class RunAnalysisAgainstRealIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = Indexer(PROJECT_ROOT).build()

    def test_all_eight_requirements_present_in_result(self):
        client = RecordingLLMClient(GENERIC_PASS)
        result = run_analysis.run_all(self.index, client, PROJECT_ROOT)
        self.assertEqual(set(result.requirement_results.keys()),
                          set(analyzer.IB_REQUIREMENTS.keys()))
        self.assertEqual(len(result.requirement_results), 8)

    def test_ib06_bypasses_the_llm_client_entirely(self):
        client = RecordingLLMClient(GENERIC_PASS)
        run_analysis.run_all(self.index, client, PROJECT_ROOT)

        # Exactly 7 calls, never 8 - IB-06 must not reach complete() at all.
        self.assertEqual(len(client.calls), 7)

        called_requirement_ids = set()
        for prompt in client.calls:
            first_line = prompt.splitlines()[0]  # "Requirement IB-XX: ..."
            rid = first_line.split(":")[0].replace("Requirement ", "").strip()
            called_requirement_ids.add(rid)

        self.assertEqual(called_requirement_ids, set(run_analysis.LLM_REQUIREMENTS))
        self.assertNotIn("IB-06", called_requirement_ids)

    def test_ib06_result_matches_the_deterministic_function_called_directly(self):
        client = RecordingLLMClient(GENERIC_PASS)
        result = run_analysis.run_all(self.index, client, PROJECT_ROOT)
        direct = analyzer.analyze_ib06_deterministic(self.index)
        self.assertEqual(result.requirement_results["IB-06"].status, direct.status)
        self.assertEqual(len(result.requirement_results["IB-06"].violations), len(direct.violations))

    def test_llm_backed_results_reflect_the_mock_response(self):
        client = RecordingLLMClient(GENERIC_PASS)
        result = run_analysis.run_all(self.index, client, PROJECT_ROOT)
        for rid in run_analysis.LLM_REQUIREMENTS:
            self.assertEqual(result.requirement_results[rid].status, "pass")
            self.assertEqual(result.requirement_results[rid].requirement_id, rid)

    def test_additional_findings_match_tech_spec_findings_called_directly(self):
        client = RecordingLLMClient(GENERIC_PASS)
        result = run_analysis.run_all(self.index, client, PROJECT_ROOT)
        direct = tech_spec_findings.assemble_tech_spec_findings(self.index)
        self.assertEqual(result.additional_findings, direct)
        self.assertEqual(len(result.additional_findings), 4)  # see test_tech_spec_findings.py

    def test_a_real_llm_backed_requirement_can_still_report_a_grounded_violation(self):
        # Prove the orchestrator doesn't flatten everything to "pass" -
        # route IB-07 (the one requirement with a known real candidate) a
        # violation response and confirm it survives the merge intact.
        ib07_violation = json.dumps({
            "status": "violation",
            "summary": "bulk_status bypasses the audit trail.",
            "violations": [{
                "location": {"file": "portal/views.py", "line": 81, "function": "bulk_status"},
                "justification": "QuerySet.update() bypasses post_save.",
                "severity": "high",
                "recommendation": "Iterate and save(), or call audit.record() explicitly.",
            }],
            "insufficient_data_reason": None,
        })

        class PerRequirementClient:
            def complete(self, system_prompt, user_prompt):
                if user_prompt.startswith("Requirement IB-07:"):
                    return ib07_violation
                return GENERIC_PASS

        result = run_analysis.run_all(self.index, PerRequirementClient(), PROJECT_ROOT)
        self.assertEqual(result.requirement_results["IB-07"].status, "violation")
        self.assertEqual(len(result.requirement_results["IB-07"].violations), 1)
        self.assertEqual(result.requirement_results["IB-07"].violations[0].location["file"], "portal/views.py")
        for rid in run_analysis.LLM_REQUIREMENTS:
            if rid != "IB-07":
                self.assertEqual(result.requirement_results[rid].status, "pass")


if __name__ == "__main__":
    unittest.main()
