"""Hand-written PCAP/PCAPNG container readers and Ethernet/IP frame decoder (struct only)."""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path

from netdash.core import CaptureReadError, PacketRecord, PacketSource

LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4, ETHERTYPE_ARP, ETHERTYPE_IPV6 = 0x0800, 0x0806, 0x86DD
PROTO_ICMP, PROTO_TCP, PROTO_UDP, PROTO_ICMPV6 = 1, 6, 17, 58
PCAPNG_SECTION_HEADER = b"\x0a\x0d\x0d\x0a"


@dataclass(frozen=True)
class RawFrame:
    """One frame as stored in the file, before any protocol decoding."""
    timestamp: float
    link_type: int
    data: bytes


class PcapReader:
    """Reads classic pcap files (either byte order, microsecond or nanosecond)."""

    # magic number read as little-endian -> (file byte order, fraction units per second)
    _MAGICS = {
        0xA1B2C3D4: ("<", 1e6), 0xA1B23C4D: ("<", 1e9),
        0xD4C3B2A1: (">", 1e6), 0x4D3CB2A1: (">", 1e9),
    }

    def read(self, data: bytes) -> list[RawFrame]:
        """Return every record in the file."""
        if len(data) < 24:
            raise CaptureReadError("file is too short for a pcap header")
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic not in self._MAGICS:
            raise CaptureReadError("not a pcap file (unknown magic number)")
        order, units = self._MAGICS[magic]
        link_type = struct.unpack_from(order + "I", data, 20)[0]  # global header: link type
        frames, offset = [], 24
        while offset < len(data):
            if offset + 16 > len(data):
                raise CaptureReadError("truncated pcap record header")
            seconds, fraction, captured, _original = struct.unpack_from(order + "IIII", data, offset)
            offset += 16
            if offset + captured > len(data):
                raise CaptureReadError("truncated pcap packet data")
            frames.append(RawFrame(seconds + fraction / units, link_type, data[offset:offset + captured]))
            offset += captured
        return frames


class PcapNgReader:
    """Reads pcapng files: section header, interface description and enhanced packet blocks."""

    def read(self, data: bytes) -> list[RawFrame]:
        """Return every enhanced packet block; other block types are skipped."""
        frames: list[RawFrame] = []
        interfaces: list[tuple[int, float]] = []  # (link type, timestamp ticks per second)
        order, offset = "", 0
        while offset < len(data):
            if offset + 12 > len(data):
                raise CaptureReadError("truncated pcapng block header")
            if data[offset:offset + 4] == PCAPNG_SECTION_HEADER:
                order = self._section_byte_order(data, offset)
                interfaces = []
            elif not order:
                raise CaptureReadError("pcapng file does not start with a section header")
            block_type, length = struct.unpack_from(order + "II", data, offset)
            if length < 12 or length % 4 or offset + length > len(data):
                raise CaptureReadError("truncated or malformed pcapng block")
            body = data[offset + 8:offset + length - 4]
            if block_type == 1:
                interfaces.append(self._interface(order, body))
            elif block_type == 6:
                frames.append(self._enhanced_packet(order, body, interfaces))
            offset += length
        return frames

    @staticmethod
    def _section_byte_order(data: bytes, offset: int) -> str:
        magic = struct.unpack_from("<I", data, offset + 8)[0]  # byte-order magic
        if magic == 0x1A2B3C4D:
            return "<"
        if magic == 0x4D3C2B1A:
            return ">"
        raise CaptureReadError("bad pcapng byte-order magic")

    @staticmethod
    def _interface(order: str, body: bytes) -> tuple[int, float]:
        link_type = struct.unpack_from(order + "H", body, 0)[0]
        ticks, pos = 1e6, 8  # default resolution is microseconds; options start at byte 8
        while pos + 4 <= len(body):
            code, size = struct.unpack_from(order + "HH", body, pos)
            if code == 0:
                break
            if code == 9 and size >= 1:  # if_tsresol
                value = body[pos + 4]
                ticks = 2.0 ** (value & 0x7F) if value & 0x80 else 10.0 ** value
            pos += 4 + size + (-size % 4)
        return link_type, ticks

    @staticmethod
    def _enhanced_packet(order: str, body: bytes, interfaces: list[tuple[int, float]]) -> RawFrame:
        interface, high, low, captured, _original = struct.unpack_from(order + "IIIII", body, 0)
        if interface >= len(interfaces):
            raise CaptureReadError("packet refers to an unknown interface")
        link_type, ticks = interfaces[interface]
        if 20 + captured > len(body):
            raise CaptureReadError("truncated pcapng packet data")
        return RawFrame(((high << 32) | low) / ticks, link_type, body[20:20 + captured])


class FrameDecoder:
    """Turns raw Ethernet frames into PacketRecords (IPv4, IPv6, ARP; TCP, UDP, ICMP)."""

    def decode(self, frame_number: int, raw: RawFrame) -> PacketRecord:
        """Decode one frame; anything it cannot understand becomes protocol "OTHER"."""
        if raw.link_type != LINKTYPE_ETHERNET:
            raise CaptureReadError(f"unsupported link type {raw.link_type}")
        try:
            return self._decode(frame_number, raw)
        except struct.error:
            return self._record(frame_number, raw, "OTHER")

    def _decode(self, number: int, raw: RawFrame) -> PacketRecord:
        data = raw.data
        if len(data) < 14:
            return self._record(number, raw, "OTHER")
        ethertype = struct.unpack_from(">H", data, 12)[0]
        if ethertype == ETHERTYPE_ARP:
            return self._record(number, raw, "ARP")
        if ethertype == ETHERTYPE_IPV4:
            ihl = (data[14] & 0x0F) * 4  # IPv4 header length in bytes
            total = struct.unpack_from(">H", data, 16)[0]
            if ihl < 20 or total < ihl:
                return self._record(number, raw, "OTHER")
            return self._ip(number, raw, data[14 + ihl:14 + total], data[23], data[26:30], data[30:34])
        if ethertype == ETHERTYPE_IPV6:
            length = struct.unpack_from(">H", data, 18)[0]  # IPv6 payload length
            return self._ip(number, raw, data[54:54 + length], data[20], data[22:38], data[38:54])
        return self._record(number, raw, "OTHER")

    def _ip(self, number: int, raw: RawFrame, payload: bytes, proto: int,
            src: bytes, dst: bytes) -> PacketRecord:
        addresses = dict(src_ip=str(ipaddress.ip_address(src)), dst_ip=str(ipaddress.ip_address(dst)))
        if proto == PROTO_TCP:
            sport, dport, seq = struct.unpack_from(">HHI", payload, 0)
            offset = (payload[12] >> 4) * 4  # TCP data offset in bytes
            if offset < 20:
                return self._record(number, raw, "OTHER", **addresses)
            return self._record(number, raw, "TCP", src_port=sport, dst_port=dport,
                                payload=payload[offset:], tcp_seq=seq, **addresses)
        if proto == PROTO_UDP:
            sport, dport = struct.unpack_from(">HH", payload, 0)
            return self._record(number, raw, "UDP", src_port=sport, dst_port=dport,
                                payload=payload[8:], **addresses)
        if proto in (PROTO_ICMP, PROTO_ICMPV6):
            return self._record(number, raw, "ICMP", **addresses)
        return self._record(number, raw, "OTHER", **addresses)

    @staticmethod
    def _record(number: int, raw: RawFrame, protocol: str, **fields) -> PacketRecord:
        values = dict(src_ip=None, dst_ip=None, src_port=None, dst_port=None)
        values.update(fields)
        return PacketRecord(frame=number, timestamp=raw.timestamp, protocol=protocol,
                            length=len(raw.data), **values)


class NativePacketSource(PacketSource):
    """Reads a pcap or pcapng file (detected from its first bytes) into PacketRecords."""

    def __init__(self, decoder: FrameDecoder | None = None) -> None:
        self._decoder = decoder or FrameDecoder()

    def read(self, path: Path) -> list[PacketRecord]:
        """Return one PacketRecord per frame, numbered from 1 in file order."""
        path = Path(path)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise CaptureReadError(f"cannot read {path.name}: {error}") from error
        reader = PcapNgReader() if data[:4] == PCAPNG_SECTION_HEADER else PcapReader()
        try:
            frames = reader.read(data)
        except (CaptureReadError, struct.error) as error:
            raise CaptureReadError(f"{path.name}: {error}") from error
        return [self._decoder.decode(number, frame) for number, frame in enumerate(frames, 1)]
