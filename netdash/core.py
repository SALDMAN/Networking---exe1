"""Shared data models and abstract interfaces. Imports nothing from the project."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path


class CaptureReadError(Exception):
    """Raised when a capture file cannot be read or decoded."""


class _Serializable:
    def to_dict(self) -> dict:
        """Return the fields as a plain dict (for the UI and a later AI layer)."""
        return asdict(self)


@dataclass(frozen=True)
class PacketRecord(_Serializable):
    """One captured frame after decoding. `frame` is 1-based, like Wireshark."""
    frame: int
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    payload: bytes = b""
    tcp_seq: int | None = None


@dataclass(frozen=True)
class EndpointCount(_Serializable):
    """How many packets involve one address."""
    address: str
    packets: int


@dataclass(frozen=True)
class CaptureSummary(_Serializable):
    """Whole-capture statistics."""
    packet_count: int
    start_time: float | None
    end_time: float | None
    duration: float
    top_endpoints: list[EndpointCount]
    protocol_counts: dict[str, int]


@dataclass(frozen=True)
class HttpTransaction(_Serializable):
    """One HTTP request and its response (response fields None if unanswered)."""
    request_frame: int
    response_frame: int | None
    method: str
    host: str | None
    uri: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    status_code: int | None
    response_time: float | None
    content_type: str | None
    request_headers: dict[str, str]
    response_headers: dict[str, str]


@dataclass(frozen=True)
class Finding(_Serializable):
    """One insight about the capture, with the frames that prove it."""
    kind: str
    message: str
    frames: list[int]


@dataclass(frozen=True)
class CaptureReport(_Serializable):
    """Everything the UI needs about one analyzed capture."""
    file_name: str
    summary: CaptureSummary
    transactions: list[HttpTransaction]
    findings: list[Finding]
    timeline: list[dict] = field(default_factory=list)


class PacketSource(ABC):
    """Reads a capture file into packet records."""

    @abstractmethod
    def read(self, path: Path) -> list[PacketRecord]:
        """Return all packets in file order; raise CaptureReadError on bad input."""


class CaptureSummarizer(ABC):
    """Computes whole-capture statistics."""

    @abstractmethod
    def summarize(self, packets: list[PacketRecord]) -> CaptureSummary:
        """Return counts, time range, top endpoints and protocol counts."""


class TransactionExtractor(ABC):
    """Finds application-level request/response pairs."""

    @abstractmethod
    def extract(self, packets: list[PacketRecord]) -> list[HttpTransaction]:
        """Return transactions sorted by request frame."""


class TimelineBuilder(ABC):
    """Buckets traffic over time."""

    @abstractmethod
    def build(self, packets: list[PacketRecord], bucket_seconds: float = 1.0) -> list[dict]:
        """Return [{"time": float, "packets": int, "bytes": int}, ...]."""


class Insight(ABC):
    """One pluggable check that turns transactions into findings."""

    @abstractmethod
    def evaluate(self, transactions: list[HttpTransaction]) -> list[Finding]:
        """Return findings, each citing frame numbers."""


class LlmError(Exception):
    """An LLM call failed (network, quota, bad reply). The message is safe to show the user."""


class LlmClient(ABC):
    """A language model behind a minimal interface; knows nothing about captures."""

    @abstractmethod
    def complete(self, system: str, prompt: str) -> str:
        """Return the model's reply text; raise LlmError on any failure."""


@dataclass(frozen=True)
class Answer(_Serializable):
    """An answer plus the capture frames it relies on."""
    text: str
    evidence_frames: list[int]    # cited frames that exist in the capture
    unverified_frames: list[int]  # cited frames that do NOT exist (possible hallucination)


class QuestionAnswerer(ABC):
    """Answers free-language questions about one analyzed capture."""

    @abstractmethod
    def ask(self, question: str, report: CaptureReport) -> Answer:
        """Return an Answer; raise LlmError if the model call fails."""
