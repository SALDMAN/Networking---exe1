"""Writes synthetic PCAP/PCAPNG files by hand (struct only) so tests know exact answers."""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

ETHERNET = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb"


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


class CaptureBuilder:
    """Collects (timestamp, frame bytes) pairs and writes them as pcap or pcapng."""

    def __init__(self) -> None:
        self._frames: list[tuple[float, bytes]] = []
        self._next_seq: dict[tuple[str, int], int] = {}

    def raw_frame(self, data: bytes, t: float) -> "CaptureBuilder":
        """Add any Ethernet frame (e.g. ARP or IPv6) at time t."""
        self._frames.append((t, data))
        return self

    def tcp_frame(self, src: tuple[str, int], dst: tuple[str, int], payload: bytes,
                  t: float, seq: int | None = None) -> "CaptureBuilder":
        """Add one IPv4/TCP frame; sequence numbers advance by payload length."""
        if seq is None:
            seq = self._next_seq.get(src, 1000)
            self._next_seq[src] = seq + len(payload)
        tcp = struct.pack(">HHIIBBHHH", src[1], dst[1], seq, 0, 5 << 4, 0x18, 65535, 0, 0)
        total = 20 + len(tcp) + len(payload)
        ip = struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
            ipaddress.IPv4Address(src[0]).packed, ipaddress.IPv4Address(dst[0]).packed,
        )
        return self.raw_frame(ETHERNET + struct.pack(">H", 0x0800) + ip + tcp + payload, t)

    def http_exchange(
        self, t: float, method: str, host: str, uri: str, status: int,
        body: bytes = b"", response_delay: float = 0.1,
        client: tuple[str, int] = ("10.0.0.2", 50000),
        server: tuple[str, int] = ("93.184.216.34", 80),
        content_type: str = "text/html", respond: bool = True,
        split_response: int = 1, shuffle_response: bool = False,
    ) -> "CaptureBuilder":
        """Add one request and (optionally) its response, response possibly split/shuffled."""
        request = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
        self.tcp_frame(client, server, request, t)
        if not respond:
            return self
        head = (f"HTTP/1.1 {status} Status\r\nContent-Type: {content_type}\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode()
        response = head + body
        size = -(-len(response) // split_response)
        base = self._next_seq.get(server, 5000)
        chunks = [(base + i, response[i:i + size]) for i in range(0, len(response), size)]
        self._next_seq[server] = base + len(response)
        if shuffle_response:
            chunks.reverse()
        for k, (seq, chunk) in enumerate(chunks):
            self.tcp_frame(server, client, chunk, t + response_delay + k * 0.001, seq=seq)
        return self

    def write_pcap(self, path: Path, byte_order: str = "little",
                   nanoseconds: bool = False) -> Path:
        """Write a classic pcap file (Ethernet link type)."""
        e = "<" if byte_order == "little" else ">"
        scale = 10**9 if nanoseconds else 10**6
        magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
        out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
        for t, data in self._frames:
            ticks = round(t * scale)
            out += struct.pack(e + "IIII", ticks // scale, ticks % scale, len(data), len(data))
            out += data
        path.write_bytes(out)
        return path

    def write_pcapng(self, path: Path, ts_resolution_power: int = 6) -> Path:
        """Write a little-endian pcapng file with one Ethernet interface."""
        def block(block_type: int, body: bytes) -> bytes:
            body = _pad4(body)
            total = len(body) + 12
            return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

        out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        options = _pad4(struct.pack("<HHB", 9, 1, ts_resolution_power)) + struct.pack("<HH", 0, 0)
        out += block(1, struct.pack("<HHI", 1, 0, 65535) + options)
        for t, data in self._frames:
            ticks = round(t * 10**ts_resolution_power)
            out += block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
                                        len(data), len(data)) + data)
        path.write_bytes(out)
        return path
