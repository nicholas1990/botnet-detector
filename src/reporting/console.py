"""Formattazione dell'output console nel formato di specifica (sez. 10)."""

import time

SEPARATOR = "=" * 50


def format_window_report(result):
    stats = result["stats"]
    indicators = result["indicators"]
    total_tcp_packets = stats.packets_sent + stats.packets_received

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
        f"Destination IP diversity (Simpson): {indicators['destination_ip_diversity']:.2f}",
        f"Destination port diversity (Simpson): {indicators['destination_port_diversity']:.2f}",
        f"Single-target port diversity (Simpson): {indicators['single_target_port_diversity']:.2f}",
        f"Beaconing regularity (Simpson): {indicators['beaconing_score']:.2f}",
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
