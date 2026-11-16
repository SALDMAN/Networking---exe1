"""The single entry point the UI (or a later API/AI layer) uses. Depends only on core."""
from __future__ import annotations

from pathlib import Path

from netdash.core import (
    CaptureReport, CaptureSummarizer, Insight, PacketSource, TimelineBuilder, TransactionExtractor,
)


class CaptureService:
    """Runs the whole analysis pipeline with injected collaborators."""

    def __init__(self, source: PacketSource, summarizer: CaptureSummarizer,
                 extractor: TransactionExtractor, insights: list[Insight],
                 timeline: TimelineBuilder) -> None:
        self._source = source
        self._summarizer = summarizer
        self._extractor = extractor
        self._insights = insights
        self._timeline = timeline

    def analyze(self, path: Path) -> CaptureReport:
        """Read the capture and return its summary, HTTP transactions, findings and timeline."""
        path = Path(path)
        packets = self._source.read(path)
        transactions = self._extractor.extract(packets)
        return CaptureReport(
            file_name=path.name,
            summary=self._summarizer.summarize(packets),
            transactions=transactions,
            findings=[f for insight in self._insights for f in insight.evaluate(transactions)],
            timeline=self._timeline.build(packets),
        )
