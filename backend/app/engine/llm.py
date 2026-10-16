"""OpenAI-compatible chat client for local / corporate LLM endpoints.

Works with vLLM, Ollama (/v1), LM Studio, llama.cpp server, LiteLLM, TGI,
OpenAI, Azure OpenAI (api-key header + api-version) and most gateways. It is
defensive about the many small incompatibilities between them:
  * `response_format=json_object` is tried, and dropped for good on a 400;
  * reasoning models' <think>…</think> blocks are stripped;
  * JSON is extracted from fenced or chatty answers;
  * retries with backoff on 429/5xx/timeouts, honouring Retry-After.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


class LlmError(RuntimeError):
    pass


@dataclass
class LlmConfig:
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    temperature: float = 0.1
    max_output_tokens: int = 1800
    context_window: int = 16384
    timeout_s: int = 180
    max_concurrency: int = 2
    json_mode: bool = True
    verify_tls: bool = True
    ca_bundle: str = ""
    auth_header: str = "bearer"          # bearer | api-key | none
    api_version: str = ""                # Azure OpenAI
    extra_headers: dict[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.model)

    @classmethod
    def from_dict(cls, d: dict) -> "LlmConfig":
        known = {k: v for k, v in (d or {}).items() if k in cls.__dataclass_fields__}
        return cls(**known)


def _strip_think(text: str) -> str:
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.I)
    return re.sub(r"^[\s\S]*?</think>", "", text, flags=re.I) if "</think>" in text else text


def extract_json(text: str) -> Any:
    text = _strip_think(text or "").strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
    if start < 0:
        raise LlmError("model did not return JSON")
    opener = text[start]
    closer = "}" if opener == "{" else "]"
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                chunk = text[start: i + 1]
                try:
                    return json.loads(chunk)
                except json.JSONDecodeError:
                    # common local-model slip: trailing commas
                    return json.loads(re.sub(r",\s*([}\]])", r"\1", chunk))
    raise LlmError("unterminated JSON in model output")


class LlmClient:
    def __init__(self, cfg: LlmConfig):
        self.cfg = cfg
        self._json_supported = cfg.json_mode
        self._sem = threading.Semaphore(max(1, cfg.max_concurrency))
        self.calls = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self.errors = 0

    # ------------------------------------------------------------ http
    def _url(self, path: str) -> str:
        base = self.cfg.base_url.rstrip("/")
        url = f"{base}/{path.lstrip('/')}"
        if self.cfg.api_version:
            url += ("&" if "?" in url else "?") + f"api-version={self.cfg.api_version}"
        return url

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.cfg.api_key:
            if self.cfg.auth_header == "api-key":
                h["api-key"] = self.cfg.api_key
            elif self.cfg.auth_header != "none":
                h["Authorization"] = f"Bearer {self.cfg.api_key}"
        h.update({k: v for k, v in (self.cfg.extra_headers or {}).items() if k and v})
        return h

    def _client(self, timeout: float | None = None) -> httpx.Client:
        verify: bool | str = self.cfg.ca_bundle if (self.cfg.verify_tls and self.cfg.ca_bundle) else self.cfg.verify_tls
        return httpx.Client(timeout=httpx.Timeout(timeout or self.cfg.timeout_s, connect=15), verify=verify)

    def list_models(self) -> list[str]:
        with self._client(30) as c:
            r = c.get(self._url("models"), headers=self._headers())
        if r.status_code >= 400:
            raise LlmError(f"GET /models → HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        items = data.get("data", data.get("models", [])) if isinstance(data, dict) else data
        out = []
        for it in items or []:
            if isinstance(it, dict):
                out.append(str(it.get("id") or it.get("name") or it.get("model")))
            else:
                out.append(str(it))
        return sorted(set(o for o in out if o and o != "None"))

    def chat(self, messages: list[dict], *, json_out: bool = True, max_tokens: int | None = None,
             temperature: float | None = None, timeout: float | None = None) -> dict:
        if not self.cfg.configured:
            raise LlmError("LLM not configured — set the base URL and model in Settings.")
        body: dict[str, Any] = {
            "model": self.cfg.model, "messages": messages, "stream": False,
            "temperature": self.cfg.temperature if temperature is None else temperature,
            "max_tokens": max_tokens or self.cfg.max_output_tokens,
        }
        if json_out and self._json_supported:
            body["response_format"] = {"type": "json_object"}
        last_err = ""
        with self._sem:
            for attempt in range(4):
                t0 = time.time()
                try:
                    with self._client(timeout) as c:
                        r = c.post(self._url("chat/completions"), headers=self._headers(), json=body)
                except (httpx.TimeoutException, httpx.TransportError) as e:
                    last_err = f"{type(e).__name__}: {e}"
                    time.sleep(min(20, 2 ** attempt))
                    continue
                if r.status_code == 400 and "response_format" in body:
                    # endpoint rejects JSON mode: stop asking for it, rely on prompt + extraction
                    self._json_supported = False
                    body.pop("response_format", None)
                    last_err = f"HTTP 400 with response_format: {r.text[:160]}"
                    continue
                if r.status_code in (408, 409, 429, 500, 502, 503, 504):
                    last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                    ra = r.headers.get("retry-after")
                    time.sleep(min(30, float(ra)) if ra and ra.replace(".", "").isdigit() else min(20, 2 ** attempt * 1.5))
                    continue
                if r.status_code >= 400:
                    self.errors += 1
                    hint = " (does the base URL need a /v1 suffix?)" if r.status_code == 404 else ""
                    raise LlmError(f"HTTP {r.status_code}{hint}: {r.text[:300]}")
                data = r.json()
                choice = (data.get("choices") or [{}])[0]
                msg = choice.get("message") or {}
                content = msg.get("content") or choice.get("text") or ""
                if not content and msg.get("reasoning_content"):
                    content = msg["reasoning_content"]
                usage = data.get("usage") or {}
                self.calls += 1
                self.tokens_in += int(usage.get("prompt_tokens") or 0)
                self.tokens_out += int(usage.get("completion_tokens") or 0)
                return {"content": _strip_think(content), "usage": usage, "latency_s": time.time() - t0,
                        "finish_reason": choice.get("finish_reason")}
        self.errors += 1
        raise LlmError(f"LLM call failed after retries: {last_err}")

    def chat_json(self, system: str, user: str, *, max_tokens: int | None = None) -> Any:
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        res = self.chat(msgs, json_out=True, max_tokens=max_tokens)
        try:
            return extract_json(res["content"])
        except (LlmError, json.JSONDecodeError):
            # one repair attempt: feed the broken answer back
            msgs += [{"role": "assistant", "content": res["content"][:6000]},
                     {"role": "user", "content": "That was not valid JSON. Reply again with ONLY the JSON object, no prose, no code fences."}]
            res = self.chat(msgs, json_out=True, max_tokens=max_tokens)
            return extract_json(res["content"])

    # ------------------------------------------------------------ budget
    def input_budget_chars(self, reserve_tokens: int = 600) -> int:
        tokens = max(1024, self.cfg.context_window - self.cfg.max_output_tokens - reserve_tokens)
        return int(tokens * 3.2)          # conservative chars/token for code

    # ------------------------------------------------------------ diagnostics
    def test_connection(self) -> dict:
        report: dict[str, Any] = {"ok": False, "base_url": self.cfg.base_url, "model": self.cfg.model, "steps": []}

        def step(name: str, ok: bool, detail: str = "", ms: float | None = None):
            report["steps"].append({"name": name, "ok": ok, "detail": detail, "ms": round(ms) if ms is not None else None})

        if not self.cfg.base_url:
            step("Configuration", False, "Base URL is empty.")
            return report
        t0 = time.time()
        try:
            models = self.list_models()
            report["models"] = models
            step("List models (GET /models)", True, f"{len(models)} model(s) available", (time.time() - t0) * 1000)
            if self.cfg.model and models and self.cfg.model not in models:
                step("Model availability", False, f"'{self.cfg.model}' not in the list returned by the endpoint.")
            elif self.cfg.model:
                step("Model availability", True, self.cfg.model)
        except Exception as e:
            report["models"] = []
            step("List models (GET /models)", False, f"{e} — some gateways do not expose /models; chat may still work.", (time.time() - t0) * 1000)
        if not self.cfg.model:
            step("Chat completion", False, "No model selected.")
            return report
        try:
            res = self.chat([{"role": "system", "content": "You are a health-check endpoint. Reply with JSON only."},
                             {"role": "user", "content": 'Return exactly {"status":"ok","sum":42} where sum is 19+23.'}],
                            json_out=True, max_tokens=60, temperature=0, timeout=min(self.cfg.timeout_s, 120))
            ms = res["latency_s"] * 1000
            step("Chat completion", True, f"finish_reason={res.get('finish_reason')}", ms)
            try:
                data = extract_json(res["content"])
                good = isinstance(data, dict) and str(data.get("sum")) == "42"
                step("Structured JSON output", good, "valid JSON, correct answer" if good else f"JSON returned but unexpected content: {str(data)[:120]}")
            except Exception:
                step("Structured JSON output", False, f"Not parseable as JSON: {res['content'][:120]!r}. Audits will still work but with more repair retries.")
            # the first call often includes loading the model into memory: measure a warm call too
            warm = self.chat([{"role": "user", "content": "Write the numbers 1 to 40 separated by commas."}],
                             json_out=False, max_tokens=120, temperature=0, timeout=min(self.cfg.timeout_s, 120))
            out_tok = int((warm.get("usage") or {}).get("completion_tokens") or 0)
            if out_tok and warm["latency_s"]:
                report["tokens_per_s"] = round(out_tok / warm["latency_s"], 1)
            step("Warm latency / throughput", True, f"{out_tok} tokens in {warm['latency_s']:.1f}s"
                 + (f" ≈ {report.get('tokens_per_s')} tok/s" if report.get("tokens_per_s") else ""), warm["latency_s"] * 1000)
            report["json_mode_supported"] = self._json_supported
            report["latency_ms"] = round(warm["latency_s"] * 1000)
            report["ok"] = True
            if self.cfg.context_window < 8192:
                step("Context window", False, f"{self.cfg.context_window} tokens is small for code review: raise it (Ollama: num_ctx) to ≥16k for better results.")
            else:
                step("Context window", True, f"{self.cfg.context_window} tokens configured")
            if ":11434" in self.cfg.base_url or "ollama" in self.cfg.base_url.lower():
                step("Ollama context length", True, "Ollama's OpenAI endpoint ignores per-request context size: start Ollama with "
                     f"OLLAMA_CONTEXT_LENGTH={max(self.cfg.context_window, 16384)} (or set num_ctx in a Modelfile), otherwise prompts are silently truncated to its default.")
        except Exception as e:
            step("Chat completion", False, str(e)[:400])
        return report
