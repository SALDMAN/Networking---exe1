# Dashboard V1 Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a small, detachable, OOP Python app that loads a PCAP/PCAPNG, extracts capture stats and HTTP transactions, and shows them in a Streamlit dashboard. The AI question box is out of scope for now.

**Architecture:** Seven modules, one responsibility each, one-way dependencies: `core` (models + abstract interfaces) <- `capture_reader`, `analysis`, `http_extractor` <- `service` (one facade, `CaptureService`) <- `ui` (Streamlit). Only `app.py` imports concrete classes and wires them together, so any part can be replaced or removed. FastAPI is not needed in V1 (see Design Decisions).

**Tech Stack:** Python >=3.10 (standard library only for capture parsing: `struct`), Streamlit, pandas (chart data), pytest. No packet library.

**Spec:** `docs/superpowers/specs/2026-11-16-dashboard-v1-design.md` (built from `networking-assignment.pdf` Part C items 23-29 and the creativity item, and `PROMPTS.md` #3-#7). Items 30-34 (AI Q&A) are deferred.

## Design Decisions (my calls, correct me)

- **Small file count (user decision).** One module per concern, not one file per class. Separation comes from classes and interfaces, not from many files.
- **No FastAPI in V1.** Streamlit calls `CaptureService` directly in-process. YAGNI. The service returns plain dataclasses with `to_dict()`, so a FastAPI layer or the AI agent can wrap it later without touching analysis code.
- **No packet library (user decision).** PCAP/PCAPNG container parsing, Ethernet/IPv4/TCP/UDP/ICMP/ARP decoding, TCP reassembly and HTTP parsing are all hand-written with `struct`. Reason: explainable line by line (the course says you must explain every line) and works on any port.
- **Scope of the hand-written decoder (updated during execution):** Ethernet (link type 1), IPv4 and IPv6 (fixed header; extension headers become protocol `"OTHER"` with addresses). The real captures turned out to be mostly IPv6, so IPv4-only would have left endpoints empty. Any other link type raises `CaptureReadError("unsupported link type N")`. No VLAN, no IP fragment reassembly (my call, YAGNI for an HTTP/80 assignment).
- **Execution deviations:** Task 8 dropped `sample_captures/` and `make_samples.py` (the real captures in `pcap-files/` serve as samples, git-ignored because one is 45 MB). `Stream` keeps two per-direction `Segment` lists instead of one tuple list.
- **Creativity extra:** an `Insight` interface with two implementations, `HttpErrorInsight` (4xx/5xx and unanswered requests) and `SlowestResponseInsight`. Each finding cites frame numbers.
- **Tests use synthetic captures** built by a small hand-written writer (`struct`) in `tests/capture_builder.py`. No network needed, and the known answers are exact.
- **Response time** = timestamp of the response's first frame minus timestamp of the request's first frame. Frame numbers are 1-based positions in the file, matching Wireshark.

## Global Constraints

- Language: Python, entry point `streamlit run app.py`.
- Input: `.pcap` and `.pcapng` files (the user picks the file).
- Streamlit is imported only in `netdash/ui.py` and `app.py`.
- Dependency direction: `core.py` imports nothing from the project. `capture_reader.py`, `analysis.py`, `http_extractor.py` import only `core`. `service.py` imports only `core`. `ui.py` imports only `core` and `service`. Only `app.py` imports concrete classes from several modules.
- No API keys, passwords or personal data anywhere in code or sample files.
- Every public class and function has a type-annotated signature and a one-line docstring (the course grades readability and explainability).
- Deliverables to keep for submission: full code, `README.md` with install and run steps, the PCAP/PCAPNG files used, `PROMPTS.md`.

## Review Focus

Failure modes the spec implies but a normal happy-path test would miss, most likely first:

1. **Keep-alive:** several HTTP transactions on one TCP connection must each pair with the right response (Task 3).
2. **Unanswered request:** a request with no response appears with `status_code=None`, `response_time=None`, not a crash or a wrong pairing (Task 3).
3. **Multi-segment / out-of-order:** a response split over several TCP segments, arriving out of order, is reassembled by sequence number (Task 3).
4. **Corrupt or non-capture file:** raises `CaptureReadError` with a readable message, and the UI shows it instead of a traceback (Tasks 2, 6).
5. **Capture with zero HTTP traffic, or zero packets:** the summary still renders, transactions list is empty, no division by zero in duration or timeline (Tasks 4, 5).

Non-IP frames (ARP, IPv6) and TLS payloads must not crash the reader or the extractor (Tasks 2 and 3).

---

## File Structure

```
yair-netwroking-assignment/
  app.py                  # Streamlit entry + composition root: builds concrete objects, runs the page
  requirements.txt        # streamlit, pandas, pytest
  pytest.ini
  README.md
  sample_captures/        # pcap/pcapng used for demo and submission
  netdash/
    __init__.py
    core.py               # dataclasses, abstract interfaces, CaptureReadError
    capture_reader.py     # PcapReader, PcapNgReader, FrameDecoder, NativePacketSource
    http_extractor.py     # TcpStreamReassembler, HttpTransactionExtractor
    analysis.py           # DefaultCaptureSummarizer, TrafficTimeline, HttpErrorInsight, SlowestResponseInsight
    service.py            # CaptureService facade
    ui.py                 # UploadPanel, SummaryPanel, ChartsPanel, TransactionsPanel, InsightsPanel, DashboardPage
  tests/
    capture_builder.py    # synthetic capture writer (test support)
    conftest.py           # fixtures basic_pcap, basic_pcapng
    test_core.py
    test_capture_reader.py
    test_http_extractor.py
    test_analysis.py
    test_service.py       # service + architecture rules + UI smoke
```

---

### Task 1: Scaffold and core

**Files:**
- Create: `requirements.txt`, `pytest.ini`, `netdash/__init__.py`, `netdash/core.py`
- Test: `tests/test_core.py`

**Interfaces:**
- Produces (all `@dataclass(frozen=True)` in `core.py`, each with `to_dict() -> dict`):
  - `PacketRecord(frame: int, timestamp: float, src_ip: str | None, dst_ip: str | None, src_port: int | None, dst_port: int | None, protocol: str, length: int, payload: bytes = b"", tcp_seq: int | None = None)`
  - `EndpointCount(address: str, packets: int)`
  - `CaptureSummary(packet_count: int, start_time: float | None, end_time: float | None, duration: float, top_endpoints: list[EndpointCount], protocol_counts: dict[str, int])`
  - `HttpTransaction(request_frame: int, response_frame: int | None, method: str, host: str | None, uri: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, status_code: int | None, response_time: float | None, content_type: str | None, request_headers: dict[str, str], response_headers: dict[str, str])`
  - `Finding(kind: str, message: str, frames: list[int])`
  - `CaptureReport(file_name: str, summary: CaptureSummary, transactions: list[HttpTransaction], findings: list[Finding], timeline: list[dict])`
- Produces (ABCs in `core.py`):
  - `PacketSource.read(path: Path) -> list[PacketRecord]`
  - `CaptureSummarizer.summarize(packets: list[PacketRecord]) -> CaptureSummary`
  - `TransactionExtractor.extract(packets: list[PacketRecord]) -> list[HttpTransaction]`
  - `TimelineBuilder.build(packets: list[PacketRecord], bucket_seconds: float = 1.0) -> list[dict]`
  - `Insight.evaluate(transactions: list[HttpTransaction]) -> list[Finding]`
- Produces: `CaptureReadError(Exception)` in `core.py`.

- [ ] **Step 1: `git init`, create `requirements.txt` (streamlit, pandas, pytest) and `pytest.ini` (`testpaths = tests`), install with `pip install -r requirements.txt`.**
- [ ] **Step 2: Write failing tests:** `test_packet_record_to_dict_round_trips_fields` (build `PacketRecord(frame=1, timestamp=1.5, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1234, dst_port=80, protocol="TCP", length=60)`, assert `to_dict()["frame"] == 1` and `["protocol"] == "TCP"`); `test_http_transaction_allows_missing_response` (`response_frame=None, status_code=None, response_time=None`, assert `to_dict()["status_code"] is None`).
- [ ] **Step 3: Run** `pytest tests/test_core.py -v`. Expected: FAIL (ImportError).
- [ ] **Step 4: Implement** the dataclasses (`to_dict` via `dataclasses.asdict`), the ABCs and `CaptureReadError`.
- [ ] **Step 5: Run** `pytest tests/test_core.py -v`. Expected: PASS.
- [ ] **Step 6: Commit** `feat: scaffold project with core models and interfaces`.

---

### Task 2: Synthetic captures and capture reader

**Files:**
- Create: `tests/capture_builder.py`, `tests/conftest.py`, `netdash/capture_reader.py`
- Test: `tests/test_capture_reader.py`

**Interfaces:**
- Consumes: `PacketSource`, `PacketRecord`, `CaptureReadError` (Task 1).
- Produces (test support, `tests/capture_builder.py`): `class CaptureBuilder` with
  - `http_exchange(self, t: float, method: str, host: str, uri: str, status: int, body: bytes = b"", response_delay: float = 0.1, client=("10.0.0.2", 50000), server=("93.184.216.34", 80), content_type: str = "text/html", respond: bool = True, split_response: int = 1, shuffle_response: bool = False) -> "CaptureBuilder"` (`split_response=N` cuts the response into N TCP segments, `shuffle_response=True` writes them out of order)
  - `raw_frame(self, data: bytes, t: float) -> "CaptureBuilder"` (any Ethernet frame bytes, e.g. ARP or IPv6)
  - `write_pcap(self, path: Path, byte_order: str = "little", nanoseconds: bool = False) -> Path`
  - `write_pcapng(self, path: Path, ts_resolution_power: int = 6) -> Path` (`if_tsresol` option: 6 = microseconds, 9 = nanoseconds)
- Produces fixtures in `conftest.py`: `basic_pcap` (path to `basic.pcap`), `basic_pcapng` (path to `basic.pcapng`). Both hold the same 3 exchanges on one keep-alive connection: `GET httpbin.org /forms/post 200`, `POST httpbin.org /post 200`, `GET httpbin.org /status/404 404`, request times t=0.0, 1.0, 2.0, response delays 0.1, 0.2, 0.3.
- Produces (in `capture_reader.py`):
  - `RawFrame` (frozen dataclass): `timestamp: float`, `link_type: int`, `data: bytes`.
  - `PcapReader.read(self, data: bytes) -> list[RawFrame]`: byte order and microsecond/nanosecond variant from the magic number (`0xa1b2c3d4`, `0xa1b23c4d`, either byte order).
  - `PcapNgReader.read(self, data: bytes) -> list[RawFrame]`: byte order from the Section Header Block, timestamp unit from the Interface Description Block `if_tsresol` option (default microseconds), reads Enhanced Packet Blocks, skips other block types.
  - `FrameDecoder.decode(self, frame_number: int, raw: RawFrame) -> PacketRecord`: Ethernet, then IPv4 (header length from IHL, total length trims Ethernet padding), then TCP (data offset, sequence number, payload), UDP, ICMP; ARP by EtherType `0x0806`. `protocol` is `"TCP"`, `"UDP"`, `"ICMP"`, `"ARP"` or `"OTHER"` (IPv6, unknown EtherTypes), never `"HTTP"`. Non-IPv4 frames get `None` IPs and ports. A frame too short for its headers becomes `"OTHER"`, never an exception. Link type other than 1 raises `CaptureReadError("unsupported link type N")`.
  - `NativePacketSource(PacketSource)`, constructor `__init__(self, decoder: FrameDecoder | None = None)`. `read(path)` picks the reader by the first 4 bytes (`0x0A0D0D0A` = PCAPNG, else PCAP) and returns one `PacketRecord` per frame, `frame` 1-based in file order. Truncated or malformed input raises `CaptureReadError` naming the file.

- [ ] **Step 1: Write failing tests** in `tests/test_capture_reader.py`:
  - `test_basic_fixtures_exist_and_are_nonempty`.
  - `test_reads_pcap_and_pcapng_identically`: same packet count, `[p.frame for p in packets] == list(range(1, n + 1))`.
  - `test_first_packet_fields`: `packets[0].protocol == "TCP"`, `dst_port == 80`.
  - `test_non_ip_frame_does_not_crash`: an ARP frame (via `raw_frame`) gives `protocol == "ARP"` and `src_ip is None`; an IPv6 frame gives `protocol == "OTHER"`.
  - `test_big_endian_and_nanosecond_pcap_timestamps`: written with `byte_order="big"` and with `nanoseconds=True`, timestamps equal the default file's (`pytest.approx(abs=1e-6)`).
  - `test_pcapng_nanosecond_resolution`: `ts_resolution_power=9` gives the same timestamps as the default.
  - `test_corrupt_file_raises_capture_read_error`: `b"not a capture"` in a `.pcap`.
  - `test_truncated_file_raises_capture_read_error`: first 30 bytes of `basic.pcap`, and `basic.pcapng` cut mid-block.
  - `test_missing_file_raises_capture_read_error`.
  - `test_short_frame_becomes_other`: a 10-byte Ethernet frame gives `protocol == "OTHER"`.
- [ ] **Step 2: Run** `pytest tests/test_capture_reader.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement `CaptureBuilder`** with `struct.pack` (Ethernet + IPv4 + TCP headers, checksums may be zero because the decoder never verifies them, sequence numbers advance by payload length; pcap = global header + record headers; pcapng = Section Header, Interface Description with `if_tsresol`, Enhanced Packet blocks). Add the fixtures.
- [ ] **Step 4: Implement** the reader classes in `capture_reader.py` with `struct.unpack_from` and explicit offsets (comment each header layout once). Wrap `OSError` and `struct.error` in `CaptureReadError`. IPv4 addresses via `".".join(map(str, raw4))`.
- [ ] **Step 5: Run** the tests. Expected: PASS.
- [ ] **Step 6: Commit** `feat: capture builder and pcap/pcapng reader`.

---

### Task 3: TCP reassembly and HTTP transactions

**Files:**
- Create: `netdash/http_extractor.py`
- Test: `tests/test_http_extractor.py`

**Interfaces:**
- Consumes: `TransactionExtractor`, `PacketRecord`, `HttpTransaction` (Task 1); `CaptureBuilder`, fixtures (Task 2).
- Produces:
  - `TcpStreamReassembler.reassemble(self, packets: list[PacketRecord]) -> list[Stream]`. `Stream` is a small dataclass in the same file: `client: tuple[str, int]`, `server: tuple[str, int]`, `client_data: bytes`, `server_data: bytes`, and ordered `segments` as `(direction, first_frame, timestamp, offset, length)` so a message offset maps back to its first frame and time. Client is the endpoint that sent the first payload-bearing packet. Segments ordered by `tcp_seq`, duplicates (retransmits) dropped.
  - `HttpTransactionExtractor(TransactionExtractor)`, constructor `__init__(self, reassembler: TcpStreamReassembler | None = None)`. Parses requests from `client_data` and responses from `server_data` in order, pairing the Nth request with the Nth response on the same stream. A message is an HTTP request if it starts with a known method token. Body length by `Content-Length`; non-HTTP payload (TLS and others) is skipped silently. Output sorted by `request_frame`. Header keys are lower-cased.

- [ ] **Step 1: Write failing tests (exact fixture values):**
  - `test_three_keepalive_transactions_paired`: `(method, uri, status_code) == [("GET","/forms/post",200), ("POST","/post",200), ("GET","/status/404",404)]`, `host == "httpbin.org"`.
  - `test_response_time_matches_fixture`: `[0.1, 0.2, 0.3]` (`pytest.approx(abs=1e-6)`).
  - `test_frames_are_first_frames_of_messages`: `response_frame > request_frame` for each, request frames strictly increase.
  - `test_unanswered_request`: `respond=False` gives one transaction with `response_frame`, `status_code`, `response_time` all `None`.
  - `test_split_out_of_order_response`: `split_response=3, shuffle_response=True, body=b"x"*3000` still gives `status_code == 200` and `response_headers["content-length"] == "3000"`.
  - `test_non_http_payload_ignored`: TLS-like bytes `b"\x16\x03\x01..."` on port 443 give zero transactions and no exception.
  - `test_pcapng_gives_same_transactions_as_pcap`.
- [ ] **Step 2: Run** `pytest tests/test_http_extractor.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the reassembler (group by sorted endpoint pair, order by `tcp_seq`) and the extractor (split on `\r\n\r\n`, parse request line and headers, consume `Content-Length` bytes, map byte offsets to first frame and timestamp).
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat: reassemble TCP streams and extract HTTP transactions`.

---

### Task 4: Summary and timeline

**Files:**
- Create: `netdash/analysis.py` (first two classes)
- Test: `tests/test_analysis.py`

**Interfaces:**
- Consumes: `CaptureSummarizer`, `TimelineBuilder`, `PacketRecord`, `CaptureSummary`, `EndpointCount` (Task 1); fixtures (Task 2).
- Produces:
  - `DefaultCaptureSummarizer(CaptureSummarizer)`, constructor `__init__(self, top_n: int = 5)`. `top_endpoints` counts each packet once per distinct IP it has as source or destination, sorted by `packets` descending then address. `protocol_counts` is `{protocol: count}`.
  - `TrafficTimeline(TimelineBuilder)`: `build(self, packets, bucket_seconds=1.0) -> list[dict]`, each dict `{"time": float, "packets": int, "bytes": int}`, buckets start at the first packet's timestamp, empty buckets in between are included with zeros.

- [ ] **Step 1: Write failing tests:** `test_summary_counts_and_duration` (`packet_count == len(packets)`, `duration == end_time - start_time`), `test_top_endpoints_sorted_and_limited` (top_n=1 gives one entry), `test_empty_capture_summary` (`packet_count == 0`, `start_time is None`, `duration == 0.0`, empty dicts), `test_timeline_buckets_include_gaps` (packets at t=0 and t=3, 1 s buckets give 4 buckets, the middle two with `packets == 0`), `test_timeline_empty_returns_empty_list`.
- [ ] **Step 2: Run** `pytest tests/test_analysis.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** both classes; use `collections.Counter`.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat: capture summary and traffic timeline`.

---

### Task 5: Insights (creativity extra)

**Files:**
- Modify: `netdash/analysis.py` (add two classes)
- Test: `tests/test_analysis.py`

**Interfaces:**
- Consumes: `Insight`, `HttpTransaction`, `Finding` (Task 1).
- Produces:
  - `HttpErrorInsight(Insight)`: one `Finding(kind="http_error")` per transaction with `status_code >= 400`, and one `Finding(kind="no_response")` per unanswered request. `frames` holds request and response frames (response omitted when `None`). Message names method, host, uri and status.
  - `SlowestResponseInsight(Insight)`: `__init__(self, top_n: int = 1)`; returns the slowest answered transactions as `Finding(kind="slow_response")`, none if there are no answered transactions.

- [ ] **Step 1: Write failing tests** with hand-built `HttpTransaction` objects: `test_404_reported_with_frames` (frames `[request_frame, response_frame]`, message contains `"404"`), `test_unanswered_reported`, `test_200_not_reported`, `test_slowest_picks_max_response_time`, `test_slowest_empty_returns_empty_list`.
- [ ] **Step 2: Run** `pytest tests/test_analysis.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** both classes.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat: http error and slowest response insights`.

---

### Task 6: Service facade and wiring

**Files:**
- Create: `netdash/service.py`
- Test: `tests/test_service.py`

**Interfaces:**
- Consumes: all ABCs and `CaptureReport` (Task 1).
- Produces: `CaptureService`, constructor `__init__(self, source: PacketSource, summarizer: CaptureSummarizer, extractor: TransactionExtractor, insights: list[Insight], timeline: TimelineBuilder)`. Method `analyze(self, path: Path) -> CaptureReport`. Depends only on abstractions.
- Produces (in `app.py`, added in Task 7): `build_capture_service() -> CaptureService`, the only place that imports concrete classes. For the tests in this task, build the service inline in a fixture from the concrete classes.

- [ ] **Step 1: Write failing tests:**
  - `test_analyze_basic_capture`: `report.file_name == "basic.pcap"`, `report.summary.packet_count > 0`, `len(report.transactions) == 3`, an `http_error` finding mentioning 404.
  - `test_service_uses_injected_collaborators`: a fake `PacketSource` returning `[]` and a fake extractor returning `[]` give an empty report with `summary.packet_count == 0`.
  - `test_no_http_capture_still_reports` (ARP-only capture): empty transactions, summary renders.
  - `test_architecture_modules_do_not_import_upward`: parse `netdash/*.py` with `ast` and assert: none except `ui.py` imports `streamlit`; `core.py` imports nothing from `netdash`; `capture_reader.py`, `analysis.py`, `http_extractor.py`, `service.py` import only `netdash.core`; `ui.py` imports only `netdash.core` and `netdash.service`.
- [ ] **Step 2: Run** `pytest tests/test_service.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `CaptureService.analyze`.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat: capture service facade and architecture rules`.

---

### Task 7: Streamlit UI and entry point

**Files:**
- Create: `netdash/ui.py`, `app.py`
- Test: `tests/test_service.py` (UI smoke tests appended)

**Interfaces:**
- Consumes: `CaptureService.analyze`, `CaptureReport`, `CaptureReadError` (Tasks 1, 6).
- Produces in `ui.py`, each class with `render(...) -> None`: `UploadPanel.render() -> Path | None` (uploads `.pcap`/`.pcapng` to a temp file and returns its path), `SummaryPanel.render(summary: CaptureSummary)` (packet count, start, end, duration, top endpoints table, protocols), `ChartsPanel.render(timeline: list[dict], protocol_counts: dict[str, int])` (traffic-over-time line chart, protocol bar chart), `TransactionsPanel.render(transactions: list[HttpTransaction])` (table with Method, Host, URI, src/dst IP and port, Status, response time, request frame, response frame; a selector for one transaction showing request and response headers), `InsightsPanel.render(findings: list[Finding])`.
- Produces: `DashboardPage(service: CaptureService, upload: UploadPanel)` with `run(self) -> None`. Catches `CaptureReadError` and shows `st.error(str(e))`.
- Produces in `app.py`: `build_capture_service() -> CaptureService` (wires `NativePacketSource`, `DefaultCaptureSummarizer`, `HttpTransactionExtractor`, `[HttpErrorInsight(), SlowestResponseInsight()]`, `TrafficTimeline`) and the script body `DashboardPage(build_capture_service(), UploadPanel()).run()`.

- [ ] **Step 1: Write failing tests** with `streamlit.testing.v1.AppTest.from_file("app.py")`: `test_app_starts_without_exception` (`not at.exception`, a title is present), `test_corrupt_file_shows_error` (`DashboardPage.run` with a stub `UploadPanel` returning a corrupt file path shows an `st.error` element and no exception). Rendering a loaded capture is verified manually in Step 5 because file upload is not scriptable in `AppTest`.
- [ ] **Step 2: Run** `pytest tests/test_service.py -v`. Expected: new tests FAIL.
- [ ] **Step 3: Implement** the panels and page. Charts use `st.line_chart` and `st.bar_chart` with pandas DataFrames built inside `ChartsPanel` only.
- [ ] **Step 4: Run** the tests. Expected: PASS.
- [ ] **Step 5: Manual check:** `streamlit run app.py`, upload the basic pcap and pcapng; the page shows three transactions, a 404 finding, both charts, and selecting a transaction shows its headers.
- [ ] **Step 6: Commit** `feat: streamlit dashboard`.

---

### Task 8: README and sample captures

**Files:**
- Create: `README.md`, `sample_captures/` (the real httpbin capture from the manual Part B once available; until then generate `synthetic_basic.pcap` and `.pcapng` with the test builder via a small script `tests/make_samples.py`)

- [ ] **Step 1: Write `README.md`:** install (`python -m venv`, `pip install -r requirements.txt`), run (`streamlit run app.py`), test (`pytest`), the module map and dependency rules, how to add a new `Insight` or swap `PacketSource`, and where the AI layer will plug in (wrap `CaptureService`, use `report.to_dict()`).
- [ ] **Step 2: Run** `pytest -v`. Expected: all PASS.
- [ ] **Step 3: Commit** `docs: readme and sample captures`.

---

## Self-Review

- **Spec coverage:** items 23 (upload, Task 7), 24 (summary, Tasks 4, 7), 25 (top endpoints and protocols, Tasks 4, 7), 26 (charts, Tasks 4, 7), 27 (detect HTTP, Task 3), 28 (transaction table fields, Tasks 3, 7), 29 (transaction detail, Task 7), creativity (Tasks 5, 7). Items 30-34 deferred by design.
- **Type consistency:** model and interface names are defined once in Task 1 and reused unchanged.
- **Proportion:** 7 source files plus tests; 8 tasks.
- **Open for the user:** which Python/OS the course environment uses (affects the version floor), and the real Part B capture for `sample_captures/`.
