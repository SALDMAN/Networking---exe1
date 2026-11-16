import pytest

from netdash.capture_reader import NativePacketSource
from netdash.http_extractor import HttpTransactionExtractor
from tests.capture_builder import CaptureBuilder


def extract(path):
    return HttpTransactionExtractor().extract(NativePacketSource().read(path))


def test_three_keepalive_transactions_paired(basic_pcap):
    transactions = extract(basic_pcap)
    assert [(t.method, t.uri, t.status_code) for t in transactions] == [
        ("GET", "/forms/post", 200), ("POST", "/post", 200), ("GET", "/status/404", 404),
    ]
    assert {t.host for t in transactions} == {"httpbin.org"}
    assert transactions[1].content_type == "application/json"
    assert (transactions[0].src_ip, transactions[0].dst_port) == ("10.0.0.2", 80)


def test_response_time_matches_fixture(basic_pcap):
    times = [t.response_time for t in extract(basic_pcap)]
    assert times == pytest.approx([0.1, 0.2, 0.3], abs=1e-6)


def test_frames_are_first_frames_of_messages(basic_pcap):
    frames = [(t.request_frame, t.response_frame) for t in extract(basic_pcap)]
    assert frames == [(1, 2), (3, 4), (5, 6)]


def test_unanswered_request(tmp_path):
    path = CaptureBuilder().http_exchange(1.0, "GET", "h.test", "/x", 200, respond=False).write_pcap(tmp_path / "a.pcap")
    (transaction,) = extract(path)
    assert (transaction.response_frame, transaction.status_code, transaction.response_time) == (None, None, None)
    assert transaction.request_frame == 1


def test_split_out_of_order_response(tmp_path):
    builder = CaptureBuilder().http_exchange(
        1.0, "GET", "h.test", "/big", 200, body=b"x" * 3000, split_response=3, shuffle_response=True)
    (transaction,) = extract(builder.write_pcap(tmp_path / "a.pcap"))
    assert transaction.status_code == 200
    assert transaction.response_headers["content-length"] == "3000"


def test_retransmitted_request_is_not_duplicated(tmp_path):
    builder = CaptureBuilder().http_exchange(1.0, "GET", "h.test", "/x", 200)
    request = b"GET /x HTTP/1.1\r\nHost: h.test\r\n\r\n"
    builder.tcp_frame(("10.0.0.2", 50000), ("93.184.216.34", 80), request, 1.5, seq=1000)
    assert len(extract(builder.write_pcap(tmp_path / "a.pcap"))) == 1


def test_non_http_payload_ignored(tmp_path):
    builder = CaptureBuilder().tcp_frame(("10.0.0.2", 50001), ("93.184.216.34", 443),
                                         b"\x16\x03\x01\x00\x05hello", 1.0)
    assert extract(builder.write_pcap(tmp_path / "a.pcap")) == []


def test_pcapng_gives_same_transactions_as_pcap(basic_pcap, basic_pcapng):
    assert extract(basic_pcapng) == extract(basic_pcap)


def test_capture_without_tcp_gives_no_transactions():
    assert HttpTransactionExtractor().extract([]) == []
