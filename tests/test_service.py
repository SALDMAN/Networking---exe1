import ast
import struct
from pathlib import Path

from netdash.analysis import DefaultCaptureSummarizer, HttpErrorInsight, SlowestResponseInsight, TrafficTimeline
from netdash.capture_reader import NativePacketSource
from netdash.core import PacketSource, TransactionExtractor
from netdash.http_extractor import HttpTransactionExtractor
from netdash.service import CaptureService
from tests.capture_builder import ETHERNET, CaptureBuilder

NETDASH = Path(__file__).resolve().parent.parent / "netdash"


def real_service() -> CaptureService:
    return CaptureService(NativePacketSource(), DefaultCaptureSummarizer(), HttpTransactionExtractor(),
                          [HttpErrorInsight(), SlowestResponseInsight()], TrafficTimeline())


def test_analyze_basic_capture(basic_pcap):
    report = real_service().analyze(basic_pcap)
    assert report.file_name == "basic.pcap"
    assert report.summary.packet_count == 6
    assert len(report.transactions) == 3
    assert any(f.kind == "http_error" and "404" in f.message for f in report.findings)
    assert any(f.kind == "slow_response" for f in report.findings)
    assert report.timeline


def test_service_uses_injected_collaborators():
    class EmptySource(PacketSource):
        def read(self, path):
            return []

    class EmptyExtractor(TransactionExtractor):
        def extract(self, packets):
            return []

    service = CaptureService(EmptySource(), DefaultCaptureSummarizer(), EmptyExtractor(), [], TrafficTimeline())
    report = service.analyze(Path("anything.pcap"))
    assert (report.summary.packet_count, report.transactions, report.findings) == (0, [], [])


def test_no_http_capture_still_reports(tmp_path):
    arp = ETHERNET + struct.pack(">H", 0x0806) + b"\x00" * 28
    path = CaptureBuilder().raw_frame(arp, 1.0).write_pcap(tmp_path / "arp.pcap")
    report = real_service().analyze(path)
    assert report.summary.packet_count == 1 and report.transactions == []
    assert report.summary.protocol_counts == {"ARP": 1}


def test_app_starts_without_exception():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(str(NETDASH.parent / "app.py"), default_timeout=30).run()
    assert not at.exception
    assert at.title[0].value == "Network Capture Dashboard"


def test_corrupt_file_shows_error(tmp_path):
    from streamlit.testing.v1 import AppTest
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"junk")

    def script(bad_path):
        from pathlib import Path
        from app import build_capture_service
        from netdash.ui import DashboardPage

        class StubUpload:
            def render(self):
                return Path(bad_path)

        DashboardPage(build_capture_service(), StubUpload()).run()

    at = AppTest.from_function(script, args=(str(bad),), default_timeout=30).run()
    assert not at.exception
    assert "bad.pcap" in at.error[0].value


def test_loaded_capture_renders_transactions(basic_pcap):
    from streamlit.testing.v1 import AppTest

    def script(path):
        from pathlib import Path
        from app import build_capture_service
        from netdash.ui import DashboardPage

        class StubUpload:
            def render(self):
                return Path(path)

        DashboardPage(build_capture_service(), StubUpload()).run()

    at = AppTest.from_function(script, args=(str(basic_pcap),), default_timeout=30).run()
    assert not at.exception
    assert [m.value for m in at.metric][0] == "6"
    assert at.selectbox[0].options[0].startswith("frame 1: GET httpbin.org/forms/post")


def _ask_script(path, with_agent):
    from pathlib import Path
    from app import build_capture_service
    from netdash.core import Answer, QuestionAnswerer
    from netdash.ui import DashboardPage

    class StubUpload:
        def render(self):
            return Path(path)

    class FakeAgent(QuestionAnswerer):
        def ask(self, question, report):
            return Answer("slowest is /status/404", [5, 6], [999])

    DashboardPage(build_capture_service(), StubUpload(), FakeAgent() if with_agent else None).run()


def test_ask_panel_shows_answer_evidence_and_unverified_warning(basic_pcap):
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_function(_ask_script, args=(str(basic_pcap), True), default_timeout=30).run()
    at.text_input[0].set_value("which was slowest?").run()
    at.button[0].click().run()
    assert not at.exception
    assert any("slowest is /status/404" in t.value for t in at.text)
    assert any("frames 5, 6" in c.value for c in at.caption)
    assert "999" in at.warning[0].value


def test_ai_off_message_when_no_agent(basic_pcap):
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_function(_ask_script, args=(str(basic_pcap), False), default_timeout=30).run()
    assert not at.exception
    assert any("LLM_API_KEY" in i.value for i in at.info)


def _imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_architecture_modules_do_not_import_upward():
    allowed = {  # module -> project modules it may import
        "__init__": set(), "core": set(), "config": set(),
        "llm": {"netdash.core", "netdash.config"}, "agent": {"netdash.core"},
        "capture_reader": {"netdash.core"}, "http_extractor": {"netdash.core"},
        "analysis": {"netdash.core"}, "service": {"netdash.core"},
        "ui": {"netdash.core", "netdash.service"},
    }
    for path in NETDASH.glob("*.py"):
        assert path.stem in allowed, f"{path.name} is not classified in the architecture rules"
        imports = _imports(path)
        project = {name for name in imports if name.split(".")[0] == "netdash"}
        assert project <= allowed[path.stem], f"{path.name} imports {project - allowed[path.stem]}"
        if path.stem != "ui":
            assert "streamlit" not in {name.split(".")[0] for name in imports}, f"{path.name} imports streamlit"
