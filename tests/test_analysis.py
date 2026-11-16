import pytest

from netdash.analysis import DefaultCaptureSummarizer, HttpErrorInsight, SlowestResponseInsight, TrafficTimeline
from netdash.capture_reader import NativePacketSource
from netdash.core import HttpTransaction, PacketRecord


def packet(t, length=100):
    return PacketRecord(frame=1, timestamp=t, src_ip="1.1.1.1", dst_ip="2.2.2.2",
                        src_port=1, dst_port=2, protocol="TCP", length=length)


def transaction(request_frame=1, response_frame=2, status=200, response_time=0.1, uri="/"):
    return HttpTransaction(
        request_frame=request_frame, response_frame=response_frame, method="GET", host="h.test",
        uri=uri, src_ip="a", src_port=1, dst_ip="b", dst_port=80, status_code=status,
        response_time=response_time, content_type=None, request_headers={}, response_headers={})


def test_summary_counts_and_duration(basic_pcap):
    packets = NativePacketSource().read(basic_pcap)
    summary = DefaultCaptureSummarizer().summarize(packets)
    assert summary.packet_count == len(packets) == 6
    assert summary.duration == pytest.approx(2.3, abs=1e-6)
    assert summary.duration == pytest.approx(summary.end_time - summary.start_time)
    assert summary.protocol_counts == {"TCP": 6}


def test_top_endpoints_sorted_and_limited(basic_pcap):
    packets = NativePacketSource().read(basic_pcap)
    top = DefaultCaptureSummarizer(top_n=1).summarize(packets).top_endpoints
    assert [(e.address, e.packets) for e in top] == [("10.0.0.2", 6)]


def test_empty_capture_summary():
    summary = DefaultCaptureSummarizer().summarize([])
    assert (summary.packet_count, summary.start_time, summary.duration) == (0, None, 0.0)
    assert summary.top_endpoints == [] and summary.protocol_counts == {}


def test_timeline_buckets_include_gaps():
    buckets = TrafficTimeline().build([packet(0.0), packet(3.0)], bucket_seconds=1.0)
    assert [b["packets"] for b in buckets] == [1, 0, 0, 1]
    assert buckets[0]["bytes"] == 100


def test_timeline_empty_returns_empty_list():
    assert TrafficTimeline().build([]) == []


def test_404_reported_with_frames():
    (finding,) = HttpErrorInsight().evaluate([transaction(3, 4, status=404, uri="/missing")])
    assert (finding.kind, finding.frames) == ("http_error", [3, 4])
    assert "404" in finding.message


def test_unanswered_reported():
    (finding,) = HttpErrorInsight().evaluate([transaction(5, None, status=None, response_time=None)])
    assert (finding.kind, finding.frames) == ("no_response", [5])


def test_200_not_reported():
    assert HttpErrorInsight().evaluate([transaction()]) == []


def test_slowest_picks_max_response_time():
    fast, slow = transaction(1, 2, response_time=0.1), transaction(3, 4, response_time=0.9)
    (finding,) = SlowestResponseInsight().evaluate([fast, slow])
    assert (finding.kind, finding.frames) == ("slow_response", [3, 4])
    assert "900 ms" in finding.message


def test_slowest_empty_returns_empty_list():
    assert SlowestResponseInsight().evaluate([]) == []
    assert SlowestResponseInsight().evaluate([transaction(1, None, None, None)]) == []
