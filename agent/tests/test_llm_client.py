"""Тесты agent/llm_client.py против локального фейкового OpenAI-совместимого сервера.

Проверяется реальный HTTP-путь клиента (urllib): формат запроса, разбор
ответа, учёт токенов, повторы при 5xx/429, откат json-режима при 400,
LLMUnavailableError при недоступности (→ код завершения 2 в main.py).

Запуск: python3 -m unittest discover -s agent/tests -v
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

AGENT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(AGENT_DIR / "tests"))

import llm_client  # noqa: E402
from fake_llm_server import FakeLLMServer  # noqa: E402

NO_SLEEP = mock.patch("llm_client.time.sleep", lambda s: None)


class OpenAICompatibleClientTests(unittest.TestCase):
    def test_success_returns_content_and_accounts_usage(self):
        with FakeLLMServer("ok", content='{"status":"pass"}') as srv:
            c = llm_client.OpenAICompatibleClient(provider="custom", api_key="k", model="m", base_url=srv.base_url, max_retries=1)
            out = c.complete("system", "user prompt")
            self.assertEqual(out, '{"status":"pass"}')
            self.assertEqual(c.usage.calls, 1)
            self.assertGreater(c.usage.prompt_tokens, 0)
            req = srv.requests[0]
            self.assertEqual(req["path"], "/v1/chat/completions")
            self.assertEqual(req["headers"]["Authorization"], "Bearer k")
            self.assertEqual(req["body"]["model"], "m")
            self.assertEqual(req["body"]["messages"][0]["role"], "system")
            self.assertEqual(req["body"]["temperature"], 0.0)
            self.assertEqual(req["body"]["response_format"], {"type": "json_object"})

    def test_retries_on_5xx_then_succeeds(self):
        with FakeLLMServer("flaky_then_ok", content="ok", fail_first=2) as srv, NO_SLEEP:
            c = llm_client.OpenAICompatibleClient(provider="custom", api_key="k", model="m", base_url=srv.base_url, max_retries=3)
            self.assertEqual(c.complete("s", "u"), "ok")
            self.assertEqual(len(srv.requests), 3)
            self.assertEqual(c.usage.retries, 2)

    def test_unavailable_after_retries_raises(self):
        with FakeLLMServer("always_429") as srv, NO_SLEEP:
            c = llm_client.OpenAICompatibleClient(provider="custom", api_key="k", model="m", base_url=srv.base_url, max_retries=2)
            with self.assertRaises(llm_client.LLMUnavailableError) as ctx:
                c.complete("s", "u")
            self.assertIn("429", str(ctx.exception))
            self.assertEqual(len(srv.requests), 3)  # 1 + 2 повтора

    def test_json_mode_fallback_on_400(self):
        with FakeLLMServer("reject_json_mode", content="plain") as srv, NO_SLEEP:
            c = llm_client.OpenAICompatibleClient(provider="custom", api_key="k", model="m", base_url=srv.base_url, max_retries=1)
            self.assertEqual(c.complete("s", "u"), "plain")
            self.assertEqual(len(srv.requests), 2)
            self.assertIn("response_format", srv.requests[0]["body"])
            self.assertNotIn("response_format", srv.requests[1]["body"])
            # второй вызов сразу без json-режима
            c.complete("s", "u")
            self.assertNotIn("response_format", srv.requests[2]["body"])

    def test_connection_refused_raises_unavailable(self):
        with NO_SLEEP:
            c = llm_client.OpenAICompatibleClient(provider="custom", api_key="k", model="m", base_url="http://127.0.0.1:9/v1", max_retries=0, timeout=2)
            with self.assertRaises(llm_client.LLMUnavailableError):
                c.complete("s", "u")

    def test_missing_key_is_config_error(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(llm_client.LLMConfigError):
                llm_client.OpenAICompatibleClient(provider="deepseek")

    def test_provider_presets(self):
        with mock.patch.dict("os.environ", {"DEEPSEEK_API_KEY": "x"}, clear=True):
            c = llm_client.OpenAICompatibleClient(provider="deepseek")
            self.assertEqual(c.endpoint, "https://api.deepseek.com/chat/completions")
            self.assertEqual(c.model, "deepseek-v4-pro")
        with mock.patch.dict("os.environ", {"DASHSCOPE_API_KEY": "x"}, clear=True):
            with self.assertRaises(llm_client.LLMConfigError) as ctx:
                llm_client.OpenAICompatibleClient(provider="qwen")
            self.assertIn("maas.aliyuncs.com", str(ctx.exception))
        env = {"DASHSCOPE_API_KEY": "x", "LLM_MODEL": "qwen3-coder-plus",
               "LLM_BASE_URL": "https://ws-1.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"}
        with mock.patch.dict("os.environ", env, clear=True):
            c = llm_client.OpenAICompatibleClient(provider="qwen")
            self.assertEqual(c.endpoint, "https://ws-1.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/chat/completions")
            self.assertEqual(c.model, "qwen3-coder-plus")

    def test_make_client_modes(self):
        self.assertIsNone(llm_client.make_client("none"))
        m = llm_client.make_client("mock")
        parsed = json.loads(m.complete("s", "u"))
        self.assertEqual(parsed["status"], "pass")


if __name__ == "__main__":
    unittest.main()
