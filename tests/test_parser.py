from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from src.capture.parser import parse_packet

LOCAL_IP = "192.168.1.10"
REMOTE_IP = "203.0.113.5"


def _tcp_packet(src, dst, sport, dport, flags):
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    packet.time = 1000.5
    return packet


def test_parse_packet_sent_syn():
    packet = _tcp_packet(LOCAL_IP, REMOTE_IP, 54321, 443, "S")

    record = parse_packet(packet, LOCAL_IP)

    assert record.direction == "sent"
    assert record.remote_ip == REMOTE_IP
    assert record.remote_port == 443
    assert record.flags == "S"
    assert record.size == len(packet)
    assert record.timestamp == 1000.5


def test_parse_packet_received_syn_ack():
    packet = _tcp_packet(REMOTE_IP, LOCAL_IP, 443, 54321, "SA")

    record = parse_packet(packet, LOCAL_IP)

    assert record.direction == "received"
    assert record.remote_ip == REMOTE_IP
    assert record.remote_port == 443


def test_parse_packet_ignores_unrelated_traffic():
    packet = _tcp_packet("10.0.0.1", "10.0.0.2", 1, 2, "S")

    assert parse_packet(packet, LOCAL_IP) is None


def test_parse_packet_ignores_non_tcp():
    packet = IP(src=LOCAL_IP, dst=REMOTE_IP) / Raw(load=b"x")

    assert parse_packet(packet, LOCAL_IP) is None
