"""LLM-клиент для OpenAI-совместимых API (DeepSeek, Qwen/DashScope, OpenAI,
любой совместимый шлюз) на стандартной библиотеке — без SDK и pip.

Поведение по ТЗ 4.7.3: недоступность модели, превышение лимитов или
неразбираемый ответ после повторных попыток → LLMUnavailableError,
которую CLI превращает в код завершения 2 без формирования отчёта.

Переменные окружения (все можно переопределить аргументами CLI):
  LLM_PROVIDER   deepseek | qwen | mock | none   (по умолчанию deepseek; организатор допускает только DeepSeek и Qwen)
  LLM_API_KEY    ключ (для deepseek также DEEPSEEK_API_KEY, для qwen — DASHSCOPE_API_KEY)
  LLM_MODEL      имя модели (по умолчанию из PROVIDERS)
  LLM_BASE_URL   базовый URL API (…/v1 или без него; путь /chat/completions добавляется сам);
                 для qwen обязателен: https://<WorkspaceId>.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1
  LLM_TIMEOUT    таймаут одного запроса, с (по умолчанию 300)
  LLM_MAX_TOKENS максимум токенов ответа (по умолчанию 8192)
  LLM_JSON_MODE  auto | on | off — просить response_format=json_object (auto: попробовать, при 400 — без него)
  LLM_THINKING   disabled | enabled | omit — режим рассуждений DeepSeek (по умолчанию disabled: в режиме
                 рассуждений они расходуют тот же max_tokens, а temperature игнорируется; omit — не передавать)

Каждый ответ возвращается как LLMText (подкласс str) с полями finish_reason,
reasoning_tokens, completion_tokens — чтобы вызывающий код мог понять, почему
ответ пуст или обрезан; эти же поля пишутся в usage.per_call и в журнал.
"""
from __future__ import annotations

import json
import os
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

PROVIDERS: dict[str, dict] = {
    "deepseek": {"base_url": "https://api.deepseek.com", "model": "deepseek-v4-pro", "key_env": ("LLM_API_KEY", "DEEPSEEK_API_KEY"),
                 "thinking": "disabled"},
    # адрес Qwen зависит от рабочего пространства Model Studio — задаётся явно через LLM_BASE_URL:
    # https://{WorkspaceId}.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1 (Сингапур) или …cn-beijing… (Пекин)
    "qwen": {"base_url": "", "model": "qwen-plus", "key_env": ("LLM_API_KEY", "DASHSCOPE_API_KEY", "QWEN_API_KEY")},
}

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class LLMText(str):
    """Текст ответа модели + метаданные ответа API (finish_reason и расход токенов)."""
    finish_reason: str | None = None
    reasoning_tokens: int | None = None
    completion_tokens: int | None = None

    @classmethod
    def build(cls, text: str, finish_reason=None, reasoning_tokens=None, completion_tokens=None) -> "LLMText":
        obj = cls(text)
        obj.finish_reason, obj.reasoning_tokens, obj.completion_tokens = finish_reason, reasoning_tokens, completion_tokens
        return obj

    def describe(self) -> str:
        parts = [f"finish_reason={self.finish_reason}"]
        if self.completion_tokens is not None:
            parts.append(f"completion_tokens={self.completion_tokens}")
        if self.reasoning_tokens is not None:
            parts.append(f"reasoning_tokens={self.reasoning_tokens}")
        parts.append(f"символов ответа={len(self.strip())}")
        return ", ".join(parts)


class LLMUnavailableError(RuntimeError):
    """Модель недоступна / лимиты / неразбираемый ответ — проверка не выполнена (код 2)."""


class LLMConfigError(RuntimeError):
    """Неверная конфигурация клиента (нет ключа, нет URL)."""


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    retries: int = 0
    wall_seconds: float = 0.0
    per_call: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "calls": self.calls, "prompt_tokens": self.prompt_tokens, "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens, "retries": self.retries, "wall_seconds": round(self.wall_seconds, 1),
            "per_call": list(self.per_call),
        }


class OpenAICompatibleClient:
    def __init__(self, provider: str = "deepseek", api_key: str | None = None, model: str | None = None,
                 base_url: str | None = None, timeout: float | None = None, max_tokens: int | None = None,
                 json_mode: str | None = None, max_retries: int = 3, temperature: float = 0.0,
                 log=None):
        provider = (provider or "deepseek").lower()
        if provider not in PROVIDERS:
            raise LLMConfigError(f"неизвестный провайдер LLM: {provider!r}; допустимы: {', '.join(PROVIDERS)}")
        preset = PROVIDERS[provider]
        self.provider = provider
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL") or preset["base_url"]).rstrip("/")
        if not self.base_url:
            hint = (" (для Qwen: https://<WorkspaceId>.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1 из консоли Model Studio)"
                    if provider == "qwen" else "")
            raise LLMConfigError(f"не задан базовый URL API (LLM_BASE_URL) для провайдера {provider}{hint}")
        self.model = model or os.environ.get("LLM_MODEL") or preset["model"]
        if not self.model:
            raise LLMConfigError("не задана модель (LLM_MODEL)")
        key = api_key
        if not key:
            for env in preset["key_env"]:
                key = os.environ.get(env)
                if key:
                    break
        if not key:
            raise LLMConfigError(f"не задан ключ API: переменная {' или '.join(preset['key_env'])}")
        self.api_key = key
        self.timeout = float(timeout or os.environ.get("LLM_TIMEOUT") or 300)
        self.max_tokens = int(max_tokens or os.environ.get("LLM_MAX_TOKENS") or 8192)
        self.json_mode = (json_mode or os.environ.get("LLM_JSON_MODE") or "auto").lower()
        self.thinking = (os.environ.get("LLM_THINKING") or preset.get("thinking") or "omit").lower()
        if self.thinking not in ("enabled", "disabled", "omit"):
            raise LLMConfigError(f"LLM_THINKING должен быть enabled, disabled или omit, а не {self.thinking!r}")
        self.max_retries = max_retries
        self.temperature = temperature
        self.usage = Usage()
        self._usage_lock = threading.Lock()
        self._log = log or (lambda msg: None)
        self._json_mode_supported = self.json_mode in ("auto", "on")

    # ------------------------------------------------------------------
    @property
    def endpoint(self) -> str:
        base = self.base_url
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"

    def _payload(self, system_prompt: str, user_prompt: str, with_json_mode: bool) -> dict:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if with_json_mode:
            payload["response_format"] = {"type": "json_object"}
        if self.thinking != "omit":
            payload["thinking"] = {"type": self.thinking}
        return payload

    def _post(self, payload: dict) -> tuple[int, dict | str]:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint, data=data, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.status
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            status = exc.code
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, body

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        attempt = 0
        with_json = self._json_mode_supported
        started = time.monotonic()
        last_error = "неизвестная ошибка"
        while True:
            attempt += 1
            try:
                status, body = self._post(self._payload(system_prompt, user_prompt, with_json))
            except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError, ConnectionError, OSError) as exc:
                last_error = f"сетевая ошибка: {exc}"
                status, body = None, None
            if status == 200 and isinstance(body, dict):
                try:
                    choice = body["choices"][0]
                    content = choice["message"].get("content")
                    if content is None and choice["message"].get("reasoning_content"):
                        content = ""
                    if not isinstance(content, str):
                        raise KeyError("content")
                except (KeyError, IndexError, TypeError) as exc:
                    last_error = f"неожиданная структура ответа API: {exc}"
                    content = None
                if content is not None:
                    text = self._account(body, started, attempt, content, choice.get("finish_reason"))
                    return text
            elif status == 400 and with_json and self.json_mode == "auto" and _mentions_response_format(body):
                # провайдер не поддерживает response_format — повторяем без него, попытка не считается
                with_json = False
                self._json_mode_supported = False
                self._log("LLM: провайдер не принял response_format=json_object, повтор без него")
                attempt -= 1
                continue
            elif status == 400 and self.thinking != "omit" and "thinking" in _short_error(body).lower():
                # провайдер не принял параметр thinking — повторяем без него, попытка не считается
                self._log(f"LLM: провайдер не принял thinking={self.thinking}, повтор без параметра")
                self.thinking = "omit"
                attempt -= 1
                continue
            elif status is not None:
                last_error = f"HTTP {status}: {_short_error(body)}"
                if status not in RETRYABLE_STATUS:
                    raise LLMUnavailableError(f"{self.provider}/{self.model}: {last_error}")
            if attempt > self.max_retries:
                raise LLMUnavailableError(f"{self.provider}/{self.model}: модель недоступна после {attempt - 1} повторов — {last_error}")
            delay = min(30.0, (2 ** attempt) + random.uniform(0, 1))
            with self._usage_lock:
                self.usage.retries += 1
            self._log(f"LLM: {last_error}; повтор через {delay:.0f} с (попытка {attempt}/{self.max_retries})")
            time.sleep(delay)

    def _account(self, body: dict, started: float, attempt: int, content: str, finish_reason) -> LLMText:
        usage = body.get("usage") or {}
        details = usage.get("completion_tokens_details") or {}
        reasoning = details.get("reasoning_tokens")
        pt = int(usage.get("prompt_tokens") or 0)
        ct = int(usage.get("completion_tokens") or 0)
        tt = int(usage.get("total_tokens") or (pt + ct))
        elapsed = time.monotonic() - started
        with self._usage_lock:
            self.usage.calls += 1
            self.usage.prompt_tokens += pt
            self.usage.completion_tokens += ct
            self.usage.total_tokens += tt
            self.usage.wall_seconds += elapsed
            self.usage.per_call.append({"prompt_tokens": pt, "completion_tokens": ct, "reasoning_tokens": reasoning,
                                        "finish_reason": finish_reason, "content_chars": len(content.strip()),
                                        "seconds": round(elapsed, 1), "attempts": attempt})
        text = LLMText.build(content, finish_reason, reasoning, ct)
        if finish_reason != "stop" or not content.strip():
            self._log(f"LLM: нештатный ответ модели — {text.describe()}")
        return text


def _mentions_response_format(body) -> bool:
    text = json.dumps(body, ensure_ascii=False) if isinstance(body, dict) else str(body)
    return "response_format" in text or "json_object" in text


def _short_error(body) -> str:
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err)[:300]
        return json.dumps(body, ensure_ascii=False)[:300]
    return str(body)[:300]


def make_client(provider: str | None, **kwargs):
    """Фабрика: None для режима без модели ('none'), MockLLMClient-совместимый
    объект для 'mock', иначе OpenAICompatibleClient."""
    provider = (provider or os.environ.get("LLM_PROVIDER") or "deepseek").lower()
    if provider in ("none", "off", "rules"):
        return None
    if provider == "mock":
        from analyzer import MockLLMClient
        return MockLLMClient(scripted_response=json.dumps({
            "status": "pass", "summary": "mock: модель не вызывалась, статус по правилам",
            "violations": [], "rule_findings_review": [], "spec_gaps": [], "need_files": [],
            "checked_files": [], "insufficient_data_reason": None,
        }, ensure_ascii=False))
    return OpenAICompatibleClient(provider=provider, **kwargs)
