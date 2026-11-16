# Network Capture Dashboard (V1)

A Streamlit dashboard that opens a PCAP/PCAPNG capture and automatically shows what we found by hand in
Wireshark: capture statistics, HTTP request/response pairs, and a few insights.
No packet library is used. The capture formats and protocol headers are decoded by hand with `struct`.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
```

Python 3.10 or newer.

## Run

```bash
streamlit run app.py
```

Open the address Streamlit prints, then choose a `.pcap` or `.pcapng` file (see `pcap-files/`).

## Test

```bash
pytest
```

Tests build their own synthetic captures (`tests/capture_builder.py`), so no network is needed.
Two tests also read the real captures in `pcap-files/` if that folder is present.

## What the dashboard shows

- Packet count, start time, end time, duration, top endpoints, protocols.
- Traffic volume over time and protocol distribution charts.
- Every HTTP transaction: Method, Host, URI, source and destination address and port, Status Code,
  response time, request and response frame numbers. Pick one to see its headers.
- Insights (our extra): HTTP errors (4xx/5xx), requests with no response, and the slowest response,
  each citing frame numbers.

## Code map

```
app.py                      entry point; the only place concrete classes are chosen
netdash/core.py             data classes, abstract interfaces, CaptureReadError
netdash/capture_reader.py   PCAP/PCAPNG reader, Ethernet/IPv4/IPv6/TCP/UDP decoder
netdash/http_extractor.py   TCP stream reassembly, HTTP request/response pairing
netdash/analysis.py         summary, timeline, insights
netdash/service.py          CaptureService: one call, analyze(path) -> CaptureReport
netdash/config.py           Settings from .env / environment (LLM_API_KEY, ...)
netdash/llm.py              GeminiClient (standard library HTTP) behind the LlmClient interface
netdash/agent.py            QuestionAgent: report -> compact JSON -> LLM -> Answer with checked evidence
netdash/ui.py               Streamlit panels and page (rendering only)
```

Dependency rules (checked by `tests/test_service.py`): `core` imports nothing from the project;
`capture_reader`, `http_extractor`, `analysis` and `service` import only `core`; `ui` imports only `core`
and `service`; only `ui` imports Streamlit. So each part can be swapped:

- A new check: subclass `Insight` and add it to the list in `app.py`.
- A different file reader: implement `PacketSource`.
- A different UI or an API: call `CaptureService.analyze(path)`; the result has `to_dict()` methods.

## Known limits

- Ethernet captures only (link type 1). IPv4 and IPv6 without extension headers.
- HTTP/1.x in plain TCP. HTTPS (TLS) payloads are not decrypted and are ignored.
- Message bodies are located with `Content-Length`; chunked bodies are not decoded.
- AI answers depend on the free Gemini quota and can be wrong; unverified frame numbers are flagged.

## AI question box

Type a free-language question under "Ask a question". The agent never sees the raw capture: it gets a compact
JSON of the extracted summary, HTTP transactions and findings, and must answer with frame numbers as evidence.
Frames it cites that do not exist in the capture are shown as a warning.

Set up the key (the app works without it; the box then says AI is off):

1. Copy `.env.example` to `.env` in the project folder.
2. Put your key after `LLM_API_KEY=`. `.env` is git-ignored: never commit it or put it in the ZIP.
3. Restart `streamlit run app.py`.

Settings (all LLM values come from `.env`; defaults live only in `netdash/config.py`):

| Name | Default | Meaning |
|---|---|---|
| `LLM_API_KEY` | none (AI off) | your key |
| `LLM_PROVIDER` | `gemini` | `gemini`, or `openai` for any OpenAI-compatible server (Cloudflare Workers AI, Groq, OpenRouter) |
| `LLM_BASE_URL` | none | server URL, needed for `openai` (Cloudflare: `https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/v1`) |
| `LLM_JSON_MODE` | `false` | ask the server for JSON output; only some models support it |
| `LLM_MODEL` | `gemini-2.5-flash` | model name |
| `LLM_TIMEOUT` | `60` | seconds to wait per answer |
| `LLM_TEMPERATURE` | `0` | 0 = most repeatable answers |
| `LLM_MAX_TRANSACTIONS` | `200` | HTTP transactions sent per question |

Real environment variables override `.env`. A bad value (for example `LLM_TIMEOUT=soon`) shows a readable
error in the question box instead of crashing. The system prompt and the JSON/header names stay in code on
purpose: they are the contract between the agent and the provider, not user settings.

Current setup: Cloudflare Workers AI (free plan, 10,000 neurons/day) through `LLM_PROVIDER=openai`, model
`@cf/google/gemma-4-26b-a4b-it`. To switch to Groq or OpenRouter, change only `LLM_BASE_URL`, `LLM_MODEL` and
`LLM_API_KEY` in `.env`. A different API style needs one new class implementing
`LlmClient.complete(system, prompt)` plus one `if` in `create_llm_client` (`netdash/llm.py`).

## Evaluation (assignment items 33-34)

`QUESTIONS.md` lists five questions with known answers, and the documented AI failure and its fix.
`python evaluate.py` asks them against `pcap-files/hasnafa (1).pcapng`, judges each answer (expected facts and
cited frames) and rewrites the Results table. It needs `LLM_API_KEY`; on a free-quota error it waits and retries.

## AI use

See `PROMPTS.md` for every prompt given while building this.
