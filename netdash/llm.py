"""LLM providers behind the LlmClient interface. Imports only core and config."""
from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from functools import partial

from netdash.config import Settings
from netdash.core import LlmClient, LlmError

Post = Callable[[str, dict, dict], dict]  # (url, headers, json body) -> parsed json reply

_HTTP_HINTS = {400: "bad request", 401: "API key rejected", 403: "API key rejected or not allowed",
               404: "wrong URL or model name", 429: "free quota exceeded, try again later"}


def post_json(url: str, headers: dict, body: dict, timeout: float, name: str) -> dict:
    """POST a JSON body and return the parsed JSON reply. Errors become LlmError without leaking secrets."""
    request = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise LlmError(f"{name} returned HTTP {error.code}: {_HTTP_HINTS.get(error.code, 'request failed')}") from None
    except (OSError, http.client.HTTPException, json.JSONDecodeError) as error:  # URLError, timeouts, resets
        raise LlmError(f"cannot reach {name}: {error}") from None


class GeminiClient(LlmClient):
    """Google Gemini over its REST API (standard library only). Asks for a JSON reply."""

    URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self, api_key: str, model: str, timeout: float, temperature: float,
                 post: Post | None = None) -> None:
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self._temperature = temperature
        self._post = post or partial(post_json, timeout=timeout, name="Gemini")

    def complete(self, system: str, prompt: str) -> str:
        """Send one prompt and return the reply text."""
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "temperature": self._temperature},
        }
        # The key goes in a header, not the URL, so it never shows up in logs or error messages.
        headers = {"x-goog-api-key": self._api_key, "Content-Type": "application/json"}
        reply = self._post(self.URL.format(model=self._model), headers, body)
        try:
            return reply["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            raise LlmError("Gemini returned no text (the answer may have been blocked)") from None


class OpenAICompatibleClient(LlmClient):
    """Any server with an OpenAI-style /chat/completions endpoint (Cloudflare Workers AI, Groq, OpenRouter...)."""

    def __init__(self, api_key: str, base_url: str, model: str, timeout: float, temperature: float,
                 json_mode: bool = False, post: Post | None = None) -> None:
        self._api_key = api_key
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._temperature = temperature
        self._json_mode = json_mode
        self._post = post or partial(post_json, timeout=timeout, name="the LLM server")

    def complete(self, system: str, prompt: str) -> str:
        """Send one prompt and return the reply text."""
        body = {
            "model": self._model,
            "temperature": self._temperature,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        }
        if self._json_mode:  # not every model supports it, so it is a setting (LLM_JSON_MODE)
            body["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        reply = self._post(self._url, headers, body)
        try:
            return reply["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LlmError("the LLM server returned no text") from None


def create_llm_client(settings: Settings) -> LlmClient | None:
    """Build the client named by settings.provider, or None when no API key is configured."""
    if not settings.api_key:
        return None
    if settings.provider == "gemini":
        return GeminiClient(settings.api_key, settings.model, settings.timeout, settings.temperature)
    if settings.provider == "openai":
        if not settings.base_url:
            raise ValueError("LLM_PROVIDER=openai needs LLM_BASE_URL")
        return OpenAICompatibleClient(settings.api_key, settings.base_url, settings.model,
                                      settings.timeout, settings.temperature, settings.json_mode)
    raise ValueError(f"unknown LLM_PROVIDER '{settings.provider}' (supported: gemini, openai)")
