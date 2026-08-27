"""Parsing dei pacchetti catturati in record strutturati."""

from dataclasses import dataclass


@dataclass
class PacketRecord:
    direction: str  # "sent" o "received", rispetto all'host monitorato
    remote_ip: str
    remote_port: int
    flags: str  # es. "S", "SA", "F", "R", "PA"
    size: int
    timestamp: float


def parse_packet(packet):
    raise NotImplementedError
