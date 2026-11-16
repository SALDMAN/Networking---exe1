"""Rebuilds TCP byte streams and pairs HTTP requests with responses (no HTTP library)."""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field

from netdash.core import HttpTransaction, PacketRecord, TransactionExtractor

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
HEADER_END = b"\r\n\r\n"


@dataclass(frozen=True)
class Segment:
    """Where one TCP segment's bytes sit inside a direction's reassembled data."""
    offset: int
    length: int
    frame: int
    timestamp: float


@dataclass
class Stream:
    """One TCP connection, reassembled per direction. The client sent the first payload."""
    client: tuple[str, int]
    server: tuple[str, int]
    client_data: bytes = b""
    server_data: bytes = b""
    client_segments: list[Segment] = field(default_factory=list)
    server_segments: list[Segment] = field(default_factory=list)


class TcpStreamReassembler:
    """Groups TCP packets into streams and orders their payload by sequence number."""

    def reassemble(self, packets: list[PacketRecord]) -> list[Stream]:
        """Return one Stream per TCP connection that carried payload."""
        groups: dict[frozenset, list[PacketRecord]] = {}
        for packet in packets:
            if packet.protocol == "TCP" and packet.payload and packet.tcp_seq is not None:
                key = frozenset({(packet.src_ip, packet.src_port), (packet.dst_ip, packet.dst_port)})
                groups.setdefault(key, []).append(packet)
        return [self._build(group) for group in groups.values()]

    def _build(self, group: list[PacketRecord]) -> Stream:
        first = min(group, key=lambda p: p.frame)
        stream = Stream(client=(first.src_ip, first.src_port), server=(first.dst_ip, first.dst_port))
        from_client = [p for p in group if (p.src_ip, p.src_port) == stream.client]
        from_server = [p for p in group if (p.src_ip, p.src_port) != stream.client]
        stream.client_data, stream.client_segments = self._join(from_client)
        stream.server_data, stream.server_segments = self._join(from_server)
        return stream

    @staticmethod
    def _join(packets: list[PacketRecord]) -> tuple[bytes, list[Segment]]:
        """Concatenate payloads in sequence order, trimming retransmitted bytes."""
        data = bytearray()
        segments: list[Segment] = []
        expected: int | None = None
        for packet in sorted(packets, key=lambda p: (p.tcp_seq, p.frame)):
            chunk = packet.payload
            if expected is not None and packet.tcp_seq < expected:
                chunk = chunk[expected - packet.tcp_seq:]  # overlap with bytes already seen
                if not chunk:
                    continue  # pure retransmission
            segments.append(Segment(len(data), len(chunk), packet.frame, packet.timestamp))
            data += chunk
            expected = packet.tcp_seq + len(packet.payload)
        return bytes(data), segments


@dataclass(frozen=True)
class _Message:
    start: int
    first_line: list[str]
    headers: dict[str, str]


class HttpTransactionExtractor(TransactionExtractor):
    """Finds HTTP requests and responses in TCP streams and pairs them in order."""

    def __init__(self, reassembler: TcpStreamReassembler | None = None) -> None:
        self._reassembler = reassembler or TcpStreamReassembler()

    def extract(self, packets: list[PacketRecord]) -> list[HttpTransaction]:
        """Return transactions sorted by the frame of their request."""
        transactions: list[HttpTransaction] = []
        for stream in self._reassembler.reassemble(packets):
            requests = self._messages(stream.client_data, is_request=True)
            responses = self._messages(stream.server_data, is_request=False)
            for index, request in enumerate(requests):
                response = responses[index] if index < len(responses) else None
                transactions.append(self._transaction(stream, request, response))
        return sorted(transactions, key=lambda t: t.request_frame)

    @staticmethod
    def _messages(data: bytes, is_request: bool) -> list[_Message]:
        """Split one direction's bytes into HTTP messages; stop at the first non-HTTP data."""
        messages: list[_Message] = []
        position = 0
        while position < len(data):
            end = data.find(HEADER_END, position)
            if end < 0:
                break
            lines = data[position:end].decode("latin-1").split("\r\n")
            first_line = lines[0].split(" ", 2)
            if is_request and first_line[0] not in HTTP_METHODS:
                break
            if not is_request and not first_line[0].startswith("HTTP/"):
                break
            headers = {}
            for line in lines[1:]:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
            messages.append(_Message(position, first_line, headers))
            body = headers.get("content-length", "0")
            position = end + len(HEADER_END) + (int(body) if body.isdigit() else 0)
        return messages

    @staticmethod
    def _locate(segments: list[Segment], offset: int) -> Segment:
        """Return the segment holding the byte at `offset` (its frame and time)."""
        return segments[bisect_right([s.offset for s in segments], offset) - 1]

    def _transaction(self, stream: Stream, request: _Message, response: _Message | None) -> HttpTransaction:
        req_segment = self._locate(stream.client_segments, request.start)
        resp_segment = self._locate(stream.server_segments, response.start) if response else None
        status = None
        if response and len(response.first_line) > 1 and response.first_line[1].isdigit():
            status = int(response.first_line[1])
        return HttpTransaction(
            request_frame=req_segment.frame,
            response_frame=resp_segment.frame if resp_segment else None,
            method=request.first_line[0],
            host=request.headers.get("host"),
            uri=request.first_line[1] if len(request.first_line) > 1 else "",
            src_ip=stream.client[0], src_port=stream.client[1],
            dst_ip=stream.server[0], dst_port=stream.server[1],
            status_code=status,
            response_time=resp_segment.timestamp - req_segment.timestamp if resp_segment else None,
            content_type=response.headers.get("content-type") if response else None,
            request_headers=request.headers,
            response_headers=response.headers if response else {},
        )
