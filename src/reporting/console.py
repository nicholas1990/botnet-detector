"""Formattazione dell'output console nel formato di specifica (sez. 10)."""

import time

from src.analysis.behavioural import compute_beaconing_score
from src.analysis.diversity import diversity_index

SEPARATOR = "=" * 50


def format_window_report(result):
    stats = result["stats"]
    total_tcp_packets = stats.packets_sent + stats.packets_received
    ip_diversity = diversity_index(stats.unique_destination_ips.values())
    port_diversity = diversity_index(stats.unique_destination_ports.values())
    beaconing_score = compute_beaconing_score(stats.syn_timestamps_by_destination)

    window_start = time.strftime("%H:%M:%S", time.localtime(result["window_start"]))
    window_end = time.strftime("%H:%M:%S", time.localtime(result["window_end"]))

    lines = [
        SEPARATOR,
        "HOST NETWORK MONITOR",
        SEPARATOR,
        "",
        f"Window: {window_start} - {window_end}",
        "",
        f"TCP packets:          {total_tcp_packets}",
        f"SYN sent:             {stats.syn_sent}",
        f"SYN-ACK received:     {stats.syn_ack_received}",
        f"FIN sent:             {stats.fin_sent}",
        f"RST received:         {stats.rst_received}",
        "",
        f"Unique destination IP: {len(stats.unique_destination_ips)}",
        f"Unique destination port: {len(stats.unique_destination_ports)}",
        f"Destination IP diversity (Simpson): {ip_diversity:.2f}",
        f"Destination port diversity (Simpson): {port_diversity:.2f}",
        f"Beaconing regularity (Simpson): {beaconing_score:.2f}",
        "",
        f"TCP Work Weight:      {result['work_weight'] * 100:.1f}%",
        f"Risk Score:           {result['score']}/100",
        "",
        f"STATUS: {result['status']}",
        "-" * 50,
    ]

    if result["reasons"]:
        lines.append("Reasons:")
        lines.extend(f"[!] {reason}" for reason in result["reasons"])

    lines.append(SEPARATOR)

    return "\n".join(lines)


def print_window_report(result):
    print(format_window_report(result))
