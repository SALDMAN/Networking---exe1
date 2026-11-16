"""Entry point and composition root: the only place concrete classes are chosen.

Run with:  streamlit run app.py
"""
from pathlib import Path

from netdash.agent import QuestionAgent, UnavailableAgent
from netdash.analysis import DefaultCaptureSummarizer, HttpErrorInsight, SlowestResponseInsight, TrafficTimeline
from netdash.capture_reader import NativePacketSource
from netdash.config import load_settings
from netdash.core import QuestionAnswerer
from netdash.http_extractor import HttpTransactionExtractor
from netdash.llm import create_llm_client
from netdash.service import CaptureService
from netdash.ui import DashboardPage, UploadPanel


def build_capture_service() -> CaptureService:
    """Wire the concrete reader, extractor, summarizer, insights and timeline together."""
    return CaptureService(
        source=NativePacketSource(),
        summarizer=DefaultCaptureSummarizer(),
        extractor=HttpTransactionExtractor(),
        insights=[HttpErrorInsight(), SlowestResponseInsight()],
        timeline=TrafficTimeline(),
    )


def build_agent() -> QuestionAnswerer | None:
    """Build the AI agent from .env settings; None (AI off) when no LLM_API_KEY is set."""
    try:
        settings = load_settings(Path(__file__).parent / ".env")
        client = create_llm_client(settings)
    except ValueError as error:  # e.g. unknown LLM_PROVIDER or a non-numeric LLM_TIMEOUT
        return UnavailableAgent(f"AI settings problem: {error}")
    return QuestionAgent(client, settings.max_transactions) if client else None


def main() -> None:
    """Build the page and render it."""
    DashboardPage(build_capture_service(), UploadPanel(), build_agent()).run()


if __name__ == "__main__":
    main()
