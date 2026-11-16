# Dashboard V1 Infrastructure: Design Spec

**Date:** 2026-11-16
**Status:** Draft for review
**Implemented by:** `docs/superpowers/plans/2026-11-16-dashboard-v1-infrastructure.md`
**Source requirements:** `networking-assignment.pdf` Part C (ג), items 23-29 and the creativity item. Prompts that shaped this spec: `PROMPTS.md` #1, #3, #4, #6, #7.

## 1. Intent and why

The networking assignment (pairs, graded on Moodle) asks for a "Dashboard V1": a Python tool that opens a PCAP/PCAPNG capture and automatically reproduces what students found by hand in Wireshark in Part B (HTTP requests, their responses, timing). Part D of the course builds on this code, so the structure matters as much as the features.

The two people building it must be able to explain every line. 40 of the 100 points go to explanations, clarity and readable code. So the goal is a small, clean, easy-to-explain codebase, not a clever one.

**What the user asked for in this phase:** an infrastructure for the code. It must be object-oriented, every part detachable from the others, and free of spaghetti code. Technologies: Python, Streamlit, and FastAPI only if needed. The AI question box (items 30-34) is deferred.

## 2. Goals

1. Load a `.pcap` or `.pcapng` file chosen by the user.
2. Show packet count, start time, end time, duration, top endpoint addresses, main protocols, and at least one chart (items 23-26).
3. Detect HTTP requests and match each to its response automatically. Show, per transaction: Method, Host, URI, source and destination IP and ports, Status Code, response time, request and response frame numbers. Let the user select one transaction and see its details (items 27-29).
4. Provide at least one creativity extra that helps a user understand the capture (HTTP error and no-response detection, and slowest-response detection, each citing frame numbers).
5. Structure the code so that:
   - each part can be replaced or removed without editing the others,
   - the later AI layer plugs in without changing analysis code.

## 3. Non-goals (for this phase)

- The AI question box and its prompts (items 30-34), including the "AI was wrong" documentation.
- Live packet capture. Only reading saved files.
- IPv6 extension headers, VLAN tags, IP fragment reassembly, and link types other than Ethernet. Such frames appear as protocol "OTHER" (or give a clear `CaptureReadError` for other link types).
- Decrypting HTTPS or analyzing TLS content.
- HTTP/2, HTTP/3, WebSocket, chunked-transfer decoding beyond what `Content-Length` handles. Such messages may be shown as incomplete but must not crash.
- Authentication, multi-user use, or persistence between sessions.
- A FastAPI service (see decision D1).

## 4. Anti-goals (a failure even if it "works")

- A Streamlit script where parsing, analysis and display are mixed in one file.
- Code the authors cannot explain line by line (for example, a large library doing the HTTP matching invisibly).
- Sending the raw PCAP to a model. The AI layer, when added, only receives extracted data.
- Any API key, password or personal data in code or sample files.
- Silent wrong answers: a corrupt file, an unanswered request, or a non-HTTP stream must show a clear message or an honest "no response", never a crash or a wrong pairing.

## 5. Constraints

- Language: Python (>=3.10). UI: Streamlit. Entry point: `streamlit run app.py`.
- Input formats: PCAP (both byte orders, microsecond and nanosecond) and PCAPNG (Enhanced Packet Blocks), Ethernet frames carrying IPv4 or IPv6.
- No packet-parsing library. The capture formats and protocol headers are decoded by hand with the standard library (`struct`).
- Must run in the course environment. Exact Python version and OS are not yet known (open question Q1), so use no dependency beyond Streamlit, pandas and pytest.
- Small file count (user decision): 7 source files, one module per concern, not one file per class.
- Dependency direction (enforced by an automated test): `core.py` imports nothing from the project; `capture_reader.py`, `analysis.py`, `http_extractor.py` and `service.py` import only `core`; `ui.py` imports only `core` and `service`; only `app.py` imports concrete classes and wires them. Streamlit is imported only in `ui.py` and `app.py`.
- Submission needs: full code, README with install and run steps, the PCAP/PCAPNG files used, `PROMPTS.md`.

## 6. Architecture

```
ui.py (Streamlit)  ->  service.py (CaptureService)  ->  core.py (interfaces + models)
                                                          ^            ^            ^
                                             capture_reader.py   http_extractor.py   analysis.py
composition root: app.py (only place that picks concrete classes)
```

Main objects:

| Object | Layer | Responsibility |
|---|---|---|
| `PacketRecord`, `HttpTransaction`, `CaptureSummary`, `Finding`, `CaptureReport` | core | Plain frozen dataclasses with `to_dict()`. The shared language between layers. |
| `PacketSource`, `CaptureSummarizer`, `TransactionExtractor`, `TimelineBuilder`, `Insight` | core.py | Abstract interfaces. |
| `PcapReader`, `PcapNgReader`, `FrameDecoder`, `NativePacketSource` | capture_reader.py | Hand-written: container formats to raw frames, frames to `PacketRecord`s, and the `PacketSource` that wires them. |
| `TcpStreamReassembler`, `HttpTransactionExtractor` | http_extractor.py | Rebuild TCP byte streams, parse and pair HTTP messages. |
| `DefaultCaptureSummarizer`, `TrafficTimeline` | analysis.py | Stats, top endpoints, protocols, timeline buckets. |
| `HttpErrorInsight`, `SlowestResponseInsight` | analysis.py | The creativity extra. |
| `CaptureService` | service.py | One entry point: `analyze(path) -> CaptureReport`. All collaborators injected. |
| `DashboardPage` and five panel classes | ui.py | Rendering only. No analysis logic. |

## 7. Behavior rules

- **Frame number:** 1-based position in the file, matching Wireshark.
- **Response time:** timestamp of the response's first frame minus timestamp of the request's first frame.
- **Pairing:** on one TCP stream, the Nth request pairs with the Nth response. This supports keep-alive connections.
- **Unanswered request:** shown with no status and no response time.
- **Retransmits and out-of-order segments:** ordered by TCP sequence number, duplicates dropped.
- **Non-HTTP payloads** (TLS, other protocols) and non-IP frames (ARP) are skipped without error.
- **Errors:** unreadable files raise `CaptureReadError`; the UI shows its message.

## 8. Approaches considered

| # | Approach | Trade-off | Verdict |
|---|---|---|---|
| A | One Streamlit script with helper functions | Fastest to write. Fails "detachable" and "no spaghetti". Hard to explain and to extend with AI. | Rejected |
| B | **Layered OOP package, Streamlit calls a service facade directly** | A few more files. Every part is testable and replaceable. No server to run. | **Chosen** |
| C | Layered package plus a FastAPI backend and a Streamlit client | Cleanest separation for a remote UI, but two processes to run, an HTTP contract to maintain and explain, more to break in the course environment. | Deferred. B leaves a seam for it: wrap `CaptureService` in FastAPI routes. |

Capture reading: no packet library (user decision, D8). The formats are simple and documented, and writing them ourselves makes every line explainable, which the grading rewards. Cost: more code to write and test, and a narrower scope (Ethernet and IPv4 only). Everything sits behind the `PacketSource` interface, so a library could still replace it by writing one class. HTTP matching is hand-written for the same reason and works on any port.

## 9. Decisions and who made them

| Id | Decision | Made by |
|---|---|---|
| D1 | No FastAPI in V1 | Claude's call (the user said "if needed"; it is not needed yet) |
| D2 | Layered OOP, dependency injection, composition root | User asked for OOP and detachable parts; the exact pattern is Claude's call |
| D3 | Hand-written TCP reassembly and HTTP parsing | Claude's call, extended by D8 |
| D4 | Creativity extra: HTTP error / no-response detection and slowest response | Claude's call |
| D5 | Synthetic captures built by a hand-written writer for tests | Claude's call |
| D6 | Python >=3.10 floor | Claude's call, pending Q1 |
| D7 | AI layer deferred | User |
| D8 | No Scapy or any packet library; PCAP/PCAPNG and protocol headers decoded by hand | User |
| D9 | Decoder scope: Ethernet + IPv4 + IPv6 (fixed header). Amended 2026-11-16: the real captures are mostly IPv6 | Claude's call, follows from D8 |
| D11 | AI layer (assignment items 30-34) added: `LlmClient`, `QuestionAnswerer`, `Answer` in `core.py`; `config.py` (.env settings, `LLM_API_KEY`), `llm.py` (`GeminiClient`), `agent.py` (`QuestionAgent`). Only `app.py` wires the key; the UI sees just `QuestionAnswerer`. The agent gets extracted JSON, never the raw PCAP, and cited frames are verified against the capture | User asked; design is Claude's call |
| D12 | Free provider: Gemini first (hit its free quota), then switched to Cloudflare Workers AI through the generic `OpenAICompatibleClient` (`LLM_PROVIDER=openai`, `LLM_BASE_URL`). GitHub Models was suggested but is retired (July 30, 2026, per GitHub docs). Providers were researched with Firecrawl | User chose Cloudflare; client design is Claude's call |
| D10 | Few files: 7 source modules instead of a package tree; wiring lives in `app.py` | User (small assignment) |

## 10. Open questions

- **Q1 (user):** Which Python version and OS does the course environment use?
- **Q2 (user):** Is the real Part B httpbin capture available? It should be added to `sample_captures/` and used for the "known answers" checks later.
- **Q3 (later, with the AI phase):** Which model or provider, and does it need to work offline?

## 11. Left to the builder

File-internal structure, exact names beyond those listed, table column styling, chart styling, wording of messages, bucket size defaults (plan uses 1 second), and how to lay out the README.

## 12. Verification

- Unit tests per component using synthetic captures with known answers (3 keep-alive transactions, exact response times 0.1, 0.2, 0.3 s).
- Architecture test that fails on any upward or forbidden import.
- Streamlit `AppTest` smoke test, plus a manual run uploading both a `.pcap` and a `.pcapng`.
- Review Focus list in the plan (keep-alive, unanswered request, out-of-order segments, corrupt file, zero HTTP or zero packets) each has a named test.
