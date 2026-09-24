import os
import sys
import tempfile
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

import main


class MainTests(unittest.TestCase):
    def test_mock_end_to_end_writes_both_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            code = main.main(["--project-root", str(PROJECT_ROOT), "--provider", "mock",
                              "--out-json", str(out / "report.json"),
                              "--out-md", str(out / "report.md")])
            self.assertIn(code, (0, 1))
            self.assertTrue((out / "report.json").is_file())
            self.assertTrue((out / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()
