"""Локальный фейковый OpenAI-совместимый сервер /chat/completions для тестов.

Сценарии (scenario):
  ok                — 200 с заданным содержимым;
  flaky_then_ok     — первые N запросов 503, потом 200 (проверка ретраев);
  always_429        — всегда 429 (проверка LLMUnavailableError);
  reject_json_mode  — 400 при наличии response_format, иначе 200 (проверка отката json-режима);
  garbage           — 200 с не-JSON текстом;
  echo_prompt       — 200 с JSON, в котором summary содержит первые 200 символов промпта.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeLLMServer:
    def __init__(self, scenario: str = "ok", content: str = "{}", fail_first: int = 2, responder=None):
        self.scenario = scenario
        self.content = content
        self.fail_first = fail_first
        self.responder = responder          # callable(request_json) -> str (content)
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                with server._lock:
                    server.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                    n = len(server.requests)
                status, payload = server._respond(body, n)
                data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def _ok(self, content: str, prompt_chars: int = 0) -> tuple[int, dict]:
        return 200, {
            "id": "chatcmpl-fake", "object": "chat.completion", "model": "fake-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": max(1, prompt_chars // 4), "completion_tokens": max(1, len(content) // 4), "total_tokens": max(2, prompt_chars // 4 + len(content) // 4)},
        }

    def _respond(self, body: dict, n: int) -> tuple[int, dict]:
        prompt_chars = sum(len(m.get("content", "")) for m in body.get("messages", []))
        if self.scenario == "flaky_then_ok" and n <= self.fail_first:
            return 503, {"error": {"message": "service unavailable (fake)"}}
        if self.scenario == "always_429":
            return 429, {"error": {"message": "rate limit exceeded (fake)"}}
        if self.scenario == "reject_json_mode" and "response_format" in body:
            return 400, {"error": {"message": "response_format is not supported (fake)"}}
        if self.scenario == "garbage":
            return self._ok("Вот мой ответ: нарушений нет, всё хорошо!", prompt_chars)
        if self.responder is not None:
            return self._ok(self.responder(body), prompt_chars)
        if self.scenario == "echo_prompt":
            user = next((m["content"] for m in body.get("messages", []) if m.get("role") == "user"), "")
            return self._ok(json.dumps({"status": "pass", "summary": user[:200], "violations": [], "rule_findings_review": [],
                                        "spec_gaps": [], "need_files": [], "checked_files": [], "insufficient_data_reason": None}, ensure_ascii=False), prompt_chars)
        return self._ok(self.content, prompt_chars)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
