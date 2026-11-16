"""Capture statistics, traffic timeline and HTTP insights. Imports only netdash.core."""
from __future__ import annotations

from collections import Counter

from netdash.core import (
    CaptureSummarizer, CaptureSummary, EndpointCount, Finding, HttpTransaction,
    Insight, PacketRecord, TimelineBuilder,
)


class DefaultCaptureSummarizer(CaptureSummarizer):
    """Counts packets, time range, top endpoints and protocols."""

    def __init__(self, top_n: int = 5) -> None:
        self._top_n = top_n

    def summarize(self, packets: list[PacketRecord]) -> CaptureSummary:
        """Summarize the capture; an empty capture gives zeros and empty tables."""
        if not packets:
            return CaptureSummary(0, None, None, 0.0, [], {})
        start = min(p.timestamp for p in packets)
        end = max(p.timestamp for p in packets)
        endpoints: Counter[str] = Counter()
        for packet in packets:
            endpoints.update({packet.src_ip, packet.dst_ip} - {None})  # once per packet per address
        top = sorted(endpoints.items(), key=lambda item: (-item[1], item[0]))[:self._top_n]
        return CaptureSummary(
            packet_count=len(packets), start_time=start, end_time=end, duration=end - start,
            top_endpoints=[EndpointCount(address, count) for address, count in top],
            protocol_counts=dict(Counter(p.protocol for p in packets)),
        )


class TrafficTimeline(TimelineBuilder):
    """Buckets packet and byte counts over time."""

    def build(self, packets: list[PacketRecord], bucket_seconds: float = 1.0) -> list[dict]:
        """Return one dict per bucket from the first packet on; gaps appear as zero buckets."""
        if not packets or bucket_seconds <= 0:
            return []
        start = min(p.timestamp for p in packets)
        count = int((max(p.timestamp for p in packets) - start) // bucket_seconds) + 1
        buckets = [{"time": start + i * bucket_seconds, "packets": 0, "bytes": 0} for i in range(count)]
        for packet in packets:
            bucket = buckets[int((packet.timestamp - start) // bucket_seconds)]
            bucket["packets"] += 1
            bucket["bytes"] += packet.length
        return buckets


def _label(transaction: HttpTransaction) -> str:
    return f"{transaction.method} {transaction.host or transaction.dst_ip}{transaction.uri}"


class HttpErrorInsight(Insight):
    """Flags HTTP error statuses (4xx/5xx) and requests that never got a response."""

    def evaluate(self, transactions: list[HttpTransaction]) -> list[Finding]:
        """Return one finding per error response or unanswered request."""
        findings = []
        for t in transactions:
            if t.response_frame is None:
                findings.append(Finding("no_response", f"No response seen for {_label(t)}",
                                        [t.request_frame]))
            elif t.status_code is not None and t.status_code >= 400:
                findings.append(Finding("http_error", f"{_label(t)} returned {t.status_code}",
                                        [t.request_frame, t.response_frame]))
        return findings


class SlowestResponseInsight(Insight):
    """Reports the slowest answered requests."""

    def __init__(self, top_n: int = 1) -> None:
        self._top_n = top_n

    def evaluate(self, transactions: list[HttpTransaction]) -> list[Finding]:
        """Return findings for the `top_n` largest response times (none if nothing answered)."""
        answered = [t for t in transactions if t.response_time is not None]
        slowest = sorted(answered, key=lambda t: t.response_time, reverse=True)[:self._top_n]
        return [Finding("slow_response", f"{_label(t)} took {t.response_time * 1000:.0f} ms",
                        [t.request_frame, t.response_frame]) for t in slowest]
