"""Streamlit panels and page. Rendering only: no parsing or analysis logic lives here."""
from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from netdash.core import (
    CaptureReadError, CaptureReport, CaptureSummary, Finding, HttpTransaction, LlmError, QuestionAnswerer,
)
from netdash.service import CaptureService

_ICONS = {"http_error": "🔴", "no_response": "🟠", "slow_response": "🐢"}


def _format_time(timestamp: float | None) -> str:
    if timestamp is None:
        return "-"
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def transaction_row(t: HttpTransaction) -> dict:
    """One table row for a transaction; shared by the transactions table and the AI evidence table."""
    return {
        "Request frame": t.request_frame, "Response frame": t.response_frame,
        "Method": t.method, "Host": t.host, "URI": t.uri,
        "Source": f"{t.src_ip}:{t.src_port}", "Destination": f"{t.dst_ip}:{t.dst_port}",
        "Status": t.status_code,
        "Response time (ms)": None if t.response_time is None else round(t.response_time * 1000, 1),
    }


class UploadPanel:
    """File picker for .pcap/.pcapng; returns the path of a saved copy."""

    def render(self) -> Path | None:
        """Show the uploader and return the uploaded file's path (None if nothing chosen)."""
        uploaded = st.file_uploader("Choose a capture file", type=["pcap", "pcapng"])
        if uploaded is None:
            return None
        file_id = getattr(uploaded, "file_id", uploaded.name)
        saved = st.session_state.get("upload")
        if saved and saved[0] == file_id:
            return saved[1]  # same upload as the previous rerun: keep the same path
        path = Path(tempfile.mkdtemp()) / Path(uploaded.name).name  # basename only: never trust a client path
        path.write_bytes(uploaded.getvalue())
        st.session_state["upload"] = (file_id, path)
        return path


class SummaryPanel:
    """Packet count, time range, top endpoints and protocols."""

    def render(self, summary: CaptureSummary) -> None:
        """Show whole-capture statistics."""
        first, second, third, fourth = st.columns(4)
        first.metric("Packets", f"{summary.packet_count:,}")
        second.metric("Duration", f"{summary.duration:.3f} s")
        third.markdown(f"**Start**  \n{_format_time(summary.start_time)}")  # metric() truncates long text
        fourth.markdown(f"**End**  \n{_format_time(summary.end_time)}")
        left, right = st.columns(2)
        left.markdown("**Top endpoints**")
        left.dataframe(pd.DataFrame([e.to_dict() for e in summary.top_endpoints],
                                    columns=["address", "packets"]), hide_index=True)
        right.markdown("**Protocols**")
        right.dataframe(pd.DataFrame(list(summary.protocol_counts.items()),
                                     columns=["protocol", "packets"]), hide_index=True)


class ChartsPanel:
    """Traffic volume over time and protocol distribution."""

    def render(self, timeline: list[dict], protocol_counts: dict[str, int]) -> None:
        """Draw the two charts (or a note when the capture is empty)."""
        if not timeline:
            st.info("No packets to chart.")
            return
        start = timeline[0]["time"]
        volume = pd.DataFrame({
            "seconds": [bucket["time"] - start for bucket in timeline],
            "bytes": [bucket["bytes"] for bucket in timeline],
        }).set_index("seconds")
        left, right = st.columns(2)
        left.markdown("**Traffic volume over time (bytes per second)**")
        left.line_chart(volume)
        right.markdown("**Protocol distribution (packets)**")
        right.bar_chart(pd.Series(protocol_counts, name="packets"))


class TransactionsPanel:
    """HTTP transactions table with a detail view for one selected transaction."""

    def render(self, transactions: list[HttpTransaction]) -> None:
        """Show every transaction and let the user pick one to inspect."""
        if not transactions:
            st.info("No HTTP transactions found in this capture.")
            return
        st.dataframe(pd.DataFrame([transaction_row(t) for t in transactions]), hide_index=True)
        index = st.selectbox(
            "Inspect a transaction", range(len(transactions)),
            format_func=lambda i: f"frame {transactions[i].request_frame}: "
                                  f"{transactions[i].method} {transactions[i].host or ''}{transactions[i].uri}",
        )
        chosen = transactions[index]
        left, right = st.columns(2)
        left.markdown(f"**Request** (frame {chosen.request_frame})")
        left.json(chosen.request_headers)
        right.markdown(f"**Response** (frame {chosen.response_frame if chosen.response_frame else '-'}, "
                       f"status {chosen.status_code if chosen.status_code else 'none'})")
        right.json(chosen.response_headers or {"note": "no response seen"})


class InsightsPanel:
    """Findings such as HTTP errors, unanswered requests and the slowest response."""

    def render(self, findings: list[Finding]) -> None:
        """List each finding with the frames that prove it."""
        if not findings:
            st.success("No problems detected.")
            return
        for finding in findings:
            frames = ", ".join(str(f) for f in finding.frames)
            st.write(f"{_ICONS.get(finding.kind, 'ℹ️')} {finding.message} (frames {frames})")


class AskPanel:
    """Free-language question box. Shows the answer, its evidence frames and any unverified ones."""

    def render(self, agent: QuestionAnswerer, report: CaptureReport) -> None:
        """Ask the agent when the button is pressed and display the result."""
        question = st.text_input("Ask a question about this capture")
        if not (st.button("Ask") and question.strip()):
            return
        try:
            with st.spinner("Asking the model..."):
                answer = agent.ask(question, report)
        except LlmError as error:
            st.error(str(error))
            return
        st.text(answer.text)  # plain text: model output is untrusted, so no markdown/links/images
        if answer.evidence_frames:
            frames = set(answer.evidence_frames)
            st.caption("Evidence: frames " + ", ".join(str(f) for f in answer.evidence_frames))
            rows = [transaction_row(t) for t in report.transactions
                    if t.request_frame in frames or t.response_frame in frames]
            if rows:
                st.dataframe(pd.DataFrame(rows), hide_index=True)
        if answer.unverified_frames:
            st.warning("The model cited frames that are not in the data it was given ("
                       + ", ".join(str(f) for f in answer.unverified_frames)
                       + "). Treat this answer with caution.")


class DashboardPage:
    """Composes the panels into the page and handles read errors."""

    def __init__(self, service: CaptureService, upload: UploadPanel,
                 agent: QuestionAnswerer | None = None) -> None:
        self._service = service
        self._upload = upload
        self._agent = agent

    def run(self) -> None:
        """Render the dashboard for the chosen capture."""
        st.set_page_config(page_title="Network Capture Dashboard", layout="wide")
        st.title("Network Capture Dashboard")
        path = self._upload.render()
        if path is None:
            st.info("Upload a .pcap or .pcapng file to begin.")
            return
        try:
            report = self._report_for(path)
        except CaptureReadError as error:
            st.error(str(error))
            return
        st.header(report.file_name)
        SummaryPanel().render(report.summary)
        ChartsPanel().render(report.timeline, report.summary.protocol_counts)
        st.subheader("HTTP transactions")
        TransactionsPanel().render(report.transactions)
        st.subheader("Insights")
        InsightsPanel().render(report.findings)
        st.subheader("Ask a question")
        if self._agent is None:
            st.info("AI questions are off. Add LLM_API_KEY to .env (see .env.example) and restart.")
        else:
            AskPanel().render(self._agent, report)

    def _report_for(self, path: Path) -> CaptureReport:
        """Analyze once per file; later reruns (widget clicks) reuse the stored report."""
        cached = st.session_state.get("report")
        if cached and cached[0] == str(path):
            return cached[1]
        report = self._service.analyze(path)
        st.session_state["report"] = (str(path), report)
        return report
