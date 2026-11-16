import pytest

from tests.capture_builder import CaptureBuilder


def _basic_builder() -> CaptureBuilder:
    """Three keep-alive exchanges: request times 100, 101, 102; delays 0.1, 0.2, 0.3."""
    return (
        CaptureBuilder()
        .http_exchange(100.0, "GET", "httpbin.org", "/forms/post", 200, body=b"<form>", response_delay=0.1)
        .http_exchange(101.0, "POST", "httpbin.org", "/post", 200, body=b"{}", response_delay=0.2,
                       content_type="application/json")
        .http_exchange(102.0, "GET", "httpbin.org", "/status/404", 404, response_delay=0.3)
    )


@pytest.fixture
def basic_builder() -> CaptureBuilder:
    return _basic_builder()


@pytest.fixture
def basic_pcap(tmp_path):
    return _basic_builder().write_pcap(tmp_path / "basic.pcap")


@pytest.fixture
def basic_pcapng(tmp_path):
    return _basic_builder().write_pcapng(tmp_path / "basic.pcapng")
