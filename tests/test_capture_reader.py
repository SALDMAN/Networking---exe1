import ipaddress
import struct
from pathlib import Path

import pytest

from netdash.capture_reader import FrameDecoder, NativePacketSource, RawFrame
from netdash.core import CaptureReadError
from tests.capture_builder import ETHERNET, CaptureBuilder

REAL_FILES = Path(__file__).resolve().parent.parent / "pcap-files"


def read(path):
    return NativePacketSource().read(path)


def test_basic_fixtures_exist_and_are_nonempty(basic_pcap, basic_pcapng):
    assert basic_pcap.stat().st_size > 0
    assert basic_pcapng.stat().st_size > 0


def test_reads_pcap_and_pcapng_identically(basic_pcap, basic_pcapng):
    a, b = read(basic_pcap), read(basic_pcapng)
    assert len(a) == len(b) > 0
    assert [p.frame for p in a] == list(range(1, len(a) + 1))
    assert [p.payload for p in a] == [p.payload for p in b]


def test_first_packet_fields(basic_pcap):
    first = read(basic_pcap)[0]
    assert first.protocol == "TCP"
    assert first.dst_port == 80
    assert first.src_ip == "10.0.0.2"
    assert first.payload.startswith(b"GET /forms/post")


def test_non_ip_frames_do_not_crash(tmp_path):
    arp = ETHERNET + struct.pack(">H", 0x0806) + b"\x00" * 28
    unknown = ETHERNET + struct.pack(">H", 0x1234) + b"\x00" * 10
    path = CaptureBuilder().raw_frame(arp, 1.0).raw_frame(unknown, 2.0).write_pcap(tmp_path / "x.pcap")
    packets = read(path)
    assert (packets[0].protocol, packets[0].src_ip) == ("ARP", None)
    assert packets[1].protocol == "OTHER"


def test_ipv6_tcp_is_decoded(tmp_path):
    src, dst = ipaddress.IPv6Address("2001:db8::1"), ipaddress.IPv6Address("2001:db8::2")
    tcp = struct.pack(">HHIIBBHHH", 5555, 80, 7, 0, 0x50, 0x10, 0, 0, 0) + b"hi"
    ip6 = struct.pack(">IHBB16s16s", 0x60000000, len(tcp), 6, 64, src.packed, dst.packed)
    frame = ETHERNET + struct.pack(">H", 0x86DD) + ip6 + tcp
    packet = read(CaptureBuilder().raw_frame(frame, 1.0).write_pcap(tmp_path / "v6.pcap"))[0]
    assert (packet.protocol, packet.src_ip, packet.dst_port) == ("TCP", "2001:db8::1", 80)
    assert packet.payload == b"hi" and packet.tcp_seq == 7


def test_big_endian_and_nanosecond_pcap_timestamps(basic_builder, tmp_path):
    base = [p.timestamp for p in read(basic_builder.write_pcap(tmp_path / "a.pcap"))]
    big = [p.timestamp for p in read(basic_builder.write_pcap(tmp_path / "b.pcap", byte_order="big"))]
    nano = [p.timestamp for p in read(basic_builder.write_pcap(tmp_path / "c.pcap", nanoseconds=True))]
    assert big == pytest.approx(base, abs=1e-6)
    assert nano == pytest.approx(base, abs=1e-6)


def test_pcapng_nanosecond_resolution(basic_builder, tmp_path):
    base = [p.timestamp for p in read(basic_builder.write_pcapng(tmp_path / "a.pcapng"))]
    nano = [p.timestamp for p in read(basic_builder.write_pcapng(tmp_path / "b.pcapng", ts_resolution_power=9))]
    assert nano == pytest.approx(base, abs=1e-6)


def test_corrupt_file_raises_capture_read_error(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"not a capture")
    with pytest.raises(CaptureReadError):
        read(path)


def test_truncated_files_raise_capture_read_error(basic_pcap, basic_pcapng, tmp_path):
    cut_pcap = tmp_path / "cut.pcap"
    cut_pcap.write_bytes(basic_pcap.read_bytes()[:30])
    cut_ng = tmp_path / "cut.pcapng"
    cut_ng.write_bytes(basic_pcapng.read_bytes()[:-5])
    for path in (cut_pcap, cut_ng):
        with pytest.raises(CaptureReadError):
            read(path)


def test_missing_file_raises_capture_read_error(tmp_path):
    with pytest.raises(CaptureReadError):
        read(tmp_path / "nope.pcap")


def test_short_frame_becomes_other():
    packet = FrameDecoder().decode(1, RawFrame(1.0, 1, b"\x00" * 10))
    assert packet.protocol == "OTHER"


def test_unsupported_link_type_raises():
    with pytest.raises(CaptureReadError, match="unsupported link type 105"):
        FrameDecoder().decode(1, RawFrame(1.0, 105, b"\x00" * 30))


@pytest.mark.skipif(not REAL_FILES.exists(), reason="real captures not present")
@pytest.mark.parametrize("name,count", [("Three_Packets (1).pcapng", 4), ("hasnafa (1).pcapng", 6498)])
def test_real_captures_read_with_expected_packet_counts(name, count):
    packets = read(REAL_FILES / name)
    assert len(packets) == count
    assert all(p.timestamp > 0 for p in packets)
