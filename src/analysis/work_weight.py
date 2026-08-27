"""Calcolo del TCP Work Weight."""


def compute_work_weight(syn_sent, fin_sent, rst_received, total_tcp_packets):
    if total_tcp_packets == 0:
        return 0.0
    return (syn_sent + fin_sent + rst_received) / total_tcp_packets
