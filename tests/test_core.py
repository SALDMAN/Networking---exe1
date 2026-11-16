from netdash.core import HttpTransaction, PacketRecord


def test_packet_record_to_dict_round_trips_fields():
    packet = PacketRecord(
        frame=1, timestamp=1.5, src_ip="1.1.1.1", dst_ip="2.2.2.2",
        src_port=1234, dst_port=80, protocol="TCP", length=60,
    )
    assert packet.to_dict()["frame"] == 1
    assert packet.to_dict()["protocol"] == "TCP"


def test_http_transaction_allows_missing_response():
    transaction = HttpTransaction(
        request_frame=3, response_frame=None, method="GET", host="h", uri="/",
        src_ip="a", src_port=1, dst_ip="b", dst_port=80, status_code=None,
        response_time=None, content_type=None, request_headers={}, response_headers={},
    )
    assert transaction.to_dict()["status_code"] is None
