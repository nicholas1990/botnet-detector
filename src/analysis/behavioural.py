"""Indicatori comportamentali: destinazioni, porte, frequenza, rapporto SYN/SYN-ACK."""

from src.config import WINDOW_SIZE


def compute_behavioural_indicators(stats):
    syn_ack_ratio = (
        stats.syn_ack_received / stats.syn_sent if stats.syn_sent > 0 else 1.0
    )

    return {
        "unique_destination_ips": len(stats.unique_destination_ips),
        "unique_destination_ports": len(stats.unique_destination_ports),
        "connections_per_second": stats.syn_sent / WINDOW_SIZE,
        "syn_ack_ratio": syn_ack_ratio,
    }
