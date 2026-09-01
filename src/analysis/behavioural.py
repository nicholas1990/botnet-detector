"""Indicatori comportamentali: destinazioni, porte, frequenza, rapporto SYN/SYN-ACK."""

from collections import Counter

from src.analysis.diversity import diversity_index, simpson_index
from src.analysis.timing import inter_arrival_bins_ms
from src.config import (
    MIN_FLOWS_PER_DESTINATION_FOR_TBF,
    MIN_PACKETS_PER_DESTINATION_FOR_DDP,
    WINDOW_SIZE,
)


def compute_single_target_port_diversity(ports_by_destination):
    """DDP per-coppia (specifiche sez. 4/6): diversita' massima delle porte
    verso una singola destinazione, tra le destinazioni con dati sufficienti.

    Alto = una destinazione sondata su molte porte diverse (port sweep).
    Basso = ogni destinazione e' raggiunta sempre sulla stessa porta (normale).
    """
    reliable_diversities = [
        diversity_index(port_counts.values())
        for port_counts in ports_by_destination.values()
        if sum(port_counts.values()) >= MIN_PACKETS_PER_DESTINATION_FOR_DDP
    ]
    return max(reliable_diversities, default=0.0)


def compute_beaconing_score(syn_timestamps_by_destination):
    """TBF (specifiche sez. 4-5): regolarita' massima degli intervalli tra
    flow consecutivi verso una stessa destinazione (concentrazione di Simpson
    sui delta binnati a 100ms), tra le destinazioni con dati sufficienti.

    Alto = intervalli quasi identici (beaconing C&C periodico).
    Basso = intervalli irregolari (traffico umano/normale).
    """
    reliable_scores = [
        simpson_index(Counter(inter_arrival_bins_ms(timestamps)).values())
        for timestamps in syn_timestamps_by_destination.values()
        if len(timestamps) >= MIN_FLOWS_PER_DESTINATION_FOR_TBF
    ]
    return max(reliable_scores, default=0.0)


def compute_behavioural_indicators(stats):
    syn_ack_ratio = (
        stats.syn_ack_received / stats.syn_sent if stats.syn_sent > 0 else 1.0
    )

    return {
        "unique_destination_ips": len(stats.unique_destination_ips),
        "unique_destination_ports": len(stats.unique_destination_ports),
        "connections_per_second": stats.syn_sent / WINDOW_SIZE,
        "syn_ack_ratio": syn_ack_ratio,
        # Simpson Diversity Index (specifiche sez. 5): quanto il traffico e'
        # disperso (1.0) o concentrato (0.0) su poche destinazioni/porte.
        # Affianca i conteggi sopra, non li sostituisce.
        "destination_ip_diversity": diversity_index(stats.unique_destination_ips.values()),
        "destination_port_diversity": diversity_index(stats.unique_destination_ports.values()),
        "single_target_port_diversity": compute_single_target_port_diversity(
            stats.ports_by_destination
        ),
        "beaconing_score": compute_beaconing_score(stats.syn_timestamps_by_destination),
    }
