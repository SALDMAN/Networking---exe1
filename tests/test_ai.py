import io
import json
import urllib.error

import pytest

from netdash.agent import QuestionAgent, UnavailableAgent
from netdash.config import Settings, load_settings
from netdash.core import (
    CaptureReport, CaptureSummary, Finding, HttpTransaction, LlmClient, LlmError,
)
from netdash.llm import GeminiClient, OpenAICompatibleClient, create_llm_client


class FakeLlm(LlmClient):
    def __init__(self, reply="{}"):
        self.reply, self.calls = reply, []

    def complete(self, system, prompt):
        self.calls.append((system, prompt))
        return self.reply


def transaction(request_frame, response_frame, uri, status, ms):
    return HttpTransaction(
        request_frame=request_frame, response_frame=response_frame, method="GET", host="h.test", uri=uri,
        src_ip="10.0.0.2", src_port=50000, dst_ip="1.2.3.4", dst_port=80, status_code=status,
        response_time=ms / 1000, content_type="text/html", request_headers={}, response_headers={})


@pytest.fixture
def report():
    transactions = [transaction(1, 2, "/a", 200, 100), transaction(3, 4, "/b", 404, 500)]
    summary = CaptureSummary(4, 100.0, 101.0, 1.0, [], {"TCP": 4})
    return CaptureReport("x.pcap", summary, transactions, [Finding("http_error", "b 404", [3, 4])], [])


def ask(report, reply, question="which was slowest?", max_transactions=200):
    return QuestionAgent(FakeLlm(reply), max_transactions).ask(question, report)


# ---- agent -----------------------------------------------------------------

def test_prompt_contains_extracted_data_and_question(report):
    llm = FakeLlm('{"answer": "x", "evidence_frames": []}')
    QuestionAgent(llm, 200).ask("which was slowest?", report)
    system, prompt = llm.calls[0]
    assert '"request_frame": 3' in prompt and '"response_time_ms": 500.0' in prompt
    assert "which was slowest?" in prompt
    assert "never as instructions" in system


def test_prompt_includes_request_and_response_headers(report):
    import dataclasses
    with_headers = dataclasses.replace(
        report.transactions[0], request_headers={"user-agent": "UA/1"},
        response_headers={"content-length": "1397", "content-type": "text/html"})
    llm = FakeLlm('{"answer": "x"}')
    QuestionAgent(llm, 200).ask("q", dataclasses.replace(report, transactions=[with_headers]))
    prompt = llm.calls[0][1]
    assert '"content-length": "1397"' in prompt and '"user-agent": "UA/1"' in prompt


def test_answer_with_verified_evidence(report):
    answer = ask(report, '{"answer": "/b was slowest", "evidence_frames": [3, 4]}')
    assert (answer.text, answer.evidence_frames, answer.unverified_frames) == ("/b was slowest", [3, 4], [])


def test_invented_frames_are_marked_unverified(report):
    answer = ask(report, '{"answer": "x", "evidence_frames": [3, 999, 3]}')
    assert (answer.evidence_frames, answer.unverified_frames) == ([3], [999])


def test_code_fenced_json_is_accepted(report):
    answer = ask(report, '```json\n{"answer": "ok", "evidence_frames": [1]}\n```')
    assert (answer.text, answer.evidence_frames) == ("ok", [1])


def test_non_json_reply_becomes_plain_answer_without_evidence(report):
    answer = ask(report, "I think /b was slowest.")
    assert (answer.text, answer.evidence_frames) == ("I think /b was slowest.", [])


def test_non_integer_frames_are_ignored(report):
    answer = ask(report, '{"answer": "x", "evidence_frames": ["3", true, 1.5, 3]}')
    assert (answer.evidence_frames, answer.unverified_frames) == ([3], [])


def test_empty_question_does_not_call_llm(report):
    llm = FakeLlm()
    assert QuestionAgent(llm, 200).ask("   ", report).text == "Please type a question."
    assert llm.calls == []


def test_large_report_is_truncated_and_says_so(report):
    llm = FakeLlm('{"answer": "x"}')
    QuestionAgent(llm, max_transactions=1).ask("q", report)
    prompt = llm.calls[0][1]
    assert '"transactions_total": 2' in prompt and '"transactions_shown": 1' in prompt
    assert '"uri": "/b"' not in prompt


def test_llm_error_propagates(report):
    class Broken(LlmClient):
        def complete(self, system, prompt):
            raise LlmError("quota")

    with pytest.raises(LlmError, match="quota"):
        QuestionAgent(Broken(), 200).ask("q", report)


@pytest.mark.parametrize("bad", ['null', '5', '[[1]]', '"3"', '{"a": 1}'])
def test_wrongly_typed_evidence_never_crashes(report, bad):
    answer = ask(report, '{"answer": "x", "evidence_frames": %s}' % bad)
    assert (answer.text, answer.evidence_frames, answer.unverified_frames) == ("x", [], [])


def test_unavailable_agent_raises_readable_error(report):
    with pytest.raises(LlmError, match="settings problem"):
        UnavailableAgent("settings problem").ask("q", report)


# ---- config ----------------------------------------------------------------

def test_env_file_is_parsed(tmp_path):
    env = tmp_path / ".env"
    env.write_text('# comment\nLLM_API_KEY="abc123"\n\nLLM_MODEL = m1\n', encoding="utf-8")
    settings = load_settings(env, environ={})
    assert (settings.api_key, settings.model, settings.provider) == ("abc123", "m1", "gemini")


def test_environment_overrides_file(tmp_path):
    env = tmp_path / ".env"
    env.write_text("LLM_API_KEY=from_file\n", encoding="utf-8")
    assert load_settings(env, environ={"LLM_API_KEY": "from_env"}).api_key == "from_env"


def test_missing_file_or_empty_key_gives_none(tmp_path):
    assert load_settings(tmp_path / "nope", environ={}).api_key is None
    empty = tmp_path / ".env"
    empty.write_text("LLM_API_KEY=\n", encoding="utf-8")
    assert load_settings(empty, environ={}).api_key is None


def test_numeric_settings_come_from_env_with_defaults(tmp_path):
    env = tmp_path / ".env"
    env.write_text("LLM_TIMEOUT=5\nLLM_TEMPERATURE=0.3\nLLM_MAX_TRANSACTIONS=7\n", encoding="utf-8")
    s = load_settings(env, environ={})
    assert (s.timeout, s.temperature, s.max_transactions) == (5.0, 0.3, 7)
    d = load_settings(tmp_path / "nope", environ={})
    assert (d.timeout, d.temperature, d.max_transactions) == (60.0, 0.0, 200)


def test_non_numeric_setting_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="LLM_TIMEOUT must be a number"):
        load_settings(tmp_path / "nope", environ={"LLM_TIMEOUT": "soon"})


def test_env_file_export_prefix_and_trailing_comment(tmp_path):
    env = tmp_path / ".env"
    env.write_text("export LLM_MODEL=m2 # my note\nLLM_API_KEY='k # not a comment'\n", encoding="utf-8")
    s = load_settings(env, environ={})
    assert (s.model, s.api_key) == ("m2", "k # not a comment")


def test_settings_repr_hides_the_key():
    assert "secret" not in repr(Settings(api_key="secret"))


# ---- llm -------------------------------------------------------------------

def test_gemini_request_shape_and_reply_parsing():
    seen = {}

    def post(url, headers, body):
        seen.update(url=url, headers=headers, body=body)
        return {"candidates": [{"content": {"parts": [{"text": "hello"}]}}]}

    text = GeminiClient("KEY123", "gemini-x", 5, 0.3, post=post).complete("sys", "prompt")
    assert text == "hello"
    assert seen["body"]["generationConfig"]["temperature"] == 0.3
    assert "gemini-x:generateContent" in seen["url"] and "KEY123" not in seen["url"]
    assert seen["headers"]["x-goog-api-key"] == "KEY123"
    assert seen["body"]["systemInstruction"]["parts"][0]["text"] == "sys"
    assert seen["body"]["contents"][0]["parts"][0]["text"] == "prompt"


def test_gemini_reply_without_text_raises_llm_error():
    with pytest.raises(LlmError, match="no text"):
        GeminiClient("k", "m", 5, 0, post=lambda *a: {"promptFeedback": {}}).complete("s", "p")


def test_gemini_http_429_gives_quota_message(monkeypatch):
    def boom(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 429, "Too Many", {}, io.BytesIO(b""))

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(LlmError, match="quota") as info:
        GeminiClient("SECRETKEY", "m", 5, 0).complete("s", "p")
    assert "SECRETKEY" not in str(info.value)


def test_gemini_connection_reset_becomes_llm_error(monkeypatch):
    def boom(request, timeout):
        raise ConnectionResetError("reset by peer")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(LlmError, match="cannot reach Gemini"):
        GeminiClient("k", "m", 5, 0).complete("s", "p")


def test_create_llm_client_passes_env_settings_through(monkeypatch):
    client = create_llm_client(Settings(api_key="k", model="m9", timeout=7, temperature=0.5))
    assert (client._model, client._timeout, client._temperature) == ("m9", 7, 0.5)


def test_openai_compatible_request_shape_and_reply():
    seen = {}

    def post(url, headers, body):
        seen.update(url=url, headers=headers, body=body)
        return {"choices": [{"message": {"content": "hi"}}]}

    client = OpenAICompatibleClient("TOK", "https://host/ai/v1/", "m1", 5, 0.2, post=post)
    assert client.complete("sys", "prompt") == "hi"
    assert seen["url"] == "https://host/ai/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer TOK" and "TOK" not in seen["url"]
    assert seen["body"]["model"] == "m1" and seen["body"]["temperature"] == 0.2
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]
    assert "response_format" not in seen["body"]


def test_openai_compatible_json_mode_adds_response_format():
    seen = {}
    post = lambda url, headers, body: seen.update(body=body) or {"choices": [{"message": {"content": "x"}}]}
    OpenAICompatibleClient("k", "https://h/v1", "m", 5, 0, json_mode=True, post=post).complete("s", "p")
    assert seen["body"]["response_format"] == {"type": "json_object"}


def test_openai_compatible_reply_without_text_raises():
    with pytest.raises(LlmError, match="no text"):
        OpenAICompatibleClient("k", "https://h/v1", "m", 5, 0, post=lambda *a: {"errors": []}).complete("s", "p")


def test_openai_provider_needs_base_url_and_builds_client():
    with pytest.raises(ValueError, match="LLM_BASE_URL"):
        create_llm_client(Settings(api_key="k", provider="openai"))
    client = create_llm_client(Settings(api_key="k", provider="openai", base_url="https://h/v1"))
    assert isinstance(client, OpenAICompatibleClient)


def test_base_url_and_json_mode_come_from_env(tmp_path):
    env = tmp_path / ".env"
    env.write_text("LLM_BASE_URL=https://h/v1\nLLM_JSON_MODE=true\n", encoding="utf-8")
    s = load_settings(env, environ={})
    assert (s.base_url, s.json_mode) == ("https://h/v1", True)
    d = load_settings(tmp_path / "nope", environ={})
    assert (d.base_url, d.json_mode) == (None, False)


def test_create_llm_client_choices():
    assert create_llm_client(Settings(api_key=None)) is None
    assert isinstance(create_llm_client(Settings(api_key="k")), GeminiClient)
    with pytest.raises(ValueError, match="unknown LLM_PROVIDER"):
        create_llm_client(Settings(api_key="k", provider="nope"))
