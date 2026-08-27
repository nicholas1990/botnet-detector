"""Parsing dei pacchetti catturati in record strutturati."""

from dataclasses import dataclass

from scapy.layers.inet import IP, TCP


@dataclass
class PacketRecord:
    direction: str  # "sent" o "received", rispetto all'host monitorato
    remote_ip: str
    remote_port: int
    flags: str  # es. "S", "SA", "F", "R", "PA"
    size: int
    timestamp: float


def parse_packet(packet, local_ip):
    """Converte un pacchetto Scapy in un PacketRecord.

    Restituisce None per i pacchetti non IP/TCP o non riconducibili
    all'host monitorato (`local_ip`).
    """
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return None

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    if ip_layer.src == local_ip:
        direction = "sent"
        remote_ip = ip_layer.dst
        remote_port = tcp_layer.dport
    elif ip_layer.dst == local_ip:
        direction = "received"
        remote_ip = ip_layer.src
        remote_port = tcp_layer.sport
    else:
        return None

    return PacketRecord(
        direction=direction,
        remote_ip=remote_ip,
        remote_port=remote_port,
        flags=str(tcp_layer.flags),
        size=len(packet),
        timestamp=float(packet.time),
    )
