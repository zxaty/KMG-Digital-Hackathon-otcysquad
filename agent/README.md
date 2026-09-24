# IB security-check agent

Run the checker from the repository root:

```powershell
$env:LLM_PROVIDER = "deepseek"
$env:LLM_API_KEY = "<your DeepSeek API key>"
python agent/main.py --project-root . --out-json report.json --out-md report.md
```

On Linux/macOS, use `export LLM_PROVIDER=deepseek` and
`export LLM_API_KEY='<your DeepSeek API key>'` before the same command.

Alternatively, `main.py` reads a `.env` file from the current directory,
the target project root, or `agent/` (existing environment variables win):

```dotenv
LLM_PROVIDER=deepseek
LLM_API_KEY=<your DeepSeek API key>
# Optional; defaults to deepseek-chat
LLM_MODEL=deepseek-chat
```

Do not commit `.env` or real API keys. For a zero-cost wiring check, set
`LLM_PROVIDER=mock`; this exercises indexing, all seven model-backed routes,
deterministic IB-06, Tech-Spec findings, report generation, and exit decisions
without making a network request.
