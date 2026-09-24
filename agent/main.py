"""Non-interactive IB security checker entrypoint."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import analyzer
from indexer import Indexer
import reporter
import run_analysis


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip().strip('"').strip("'")
        if name and name not in os.environ:
            os.environ[name] = value


def git_commit(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
            stderr=subprocess.DEVNULL, timeout=10,
        ).strip()
    except Exception:
        return "unknown"


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--out-json", type=Path, default=Path("report.json"))
    parser.add_argument("--out-md", type=Path, default=Path("report.md"))
    parser.add_argument("--provider", default=None)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    root = args.project_root.resolve()
    load_dotenv(Path.cwd() / ".env")
    load_dotenv(root / ".env")
    load_dotenv(Path(__file__).resolve().parent / ".env")
    provider = (args.provider or os.environ.get("LLM_PROVIDER") or "").lower()
    started_wall = time.monotonic()
    started = datetime.now(timezone.utc)
    try:
        index = Indexer(root).build()
        if provider == "deepseek":
            client = analyzer.DeepSeekClient(model=os.environ.get("LLM_MODEL", "deepseek-chat"))
            model = f"deepseek/{client.model}"
        elif provider == "mock":
            response = json.dumps({"status": "pass", "summary": "mock pass", "violations": [],
                                   "insufficient_data_reason": None})
            client = analyzer.MockLLMClient(response)
            model = "mock/scripted"
        else:
            raise RuntimeError("LLM_PROVIDER must be 'deepseek' (or 'mock' for offline wiring tests)")
        result = run_analysis.run_all(index, client, root)
        finished = datetime.now(timezone.utc)
        usage = {name: getattr(client, name, 0) for name in
                 ("calls", "prompt_tokens", "completion_tokens", "total_tokens")}
        if provider == "mock":
            usage["calls"] = len(run_analysis.LLM_REQUIREMENTS)
        report, exit_code = reporter.build_report(
            result, commit=git_commit(root), started_at=started.isoformat(),
            finished_at=finished.isoformat(), duration_seconds=time.monotonic() - started_wall,
            model=model, usage=usage,
        )
        reporter.write_reports(report, args.out_json, args.out_md)
        violated = [rid for rid, status in report["summary"]["requirements_status"].items()
                    if status == "violation"]
        print(f"exit_code={exit_code} violations_count={len(report['violations'])} "
              f"violated_requirements={','.join(violated) or 'none'}")
        print(f"duration_seconds={report['meta']['duration_seconds']} calls={usage['calls']} "
              f"prompt_tokens={usage['prompt_tokens']} completion_tokens={usage['completion_tokens']} "
              f"total_tokens={usage['total_tokens']}")
        return exit_code
    except Exception as exc:
        print(f"agent error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
