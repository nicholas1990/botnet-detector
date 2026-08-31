from src.analysis.behavioural import (
    compute_behavioural_indicators,
    compute_single_target_port_diversity,
)
from src.analysis.statistics import StatisticsWindow
from src.capture.parser import PacketRecord
from src.config import WINDOW_SIZE


def test_normal_traffic_has_full_syn_ack_ratio_and_few_destinations():
    window = StatisticsWindow()
    window.update(PacketRecord("sent", "1.2.3.4", 443, "S", 60, 0.0))
    window.update(PacketRecord("received", "1.2.3.4", 443, "SA", 60, 0.0))

    indicators = compute_behavioural_indicators(window)

    assert indicators["unique_destination_ips"] == 1
    assert indicators["unique_destination_ports"] == 1
    assert indicators["syn_ack_ratio"] == 1.0
    assert indicators["connections_per_second"] == 1 / WINDOW_SIZE
    assert indicators["destination_ip_diversity"] == 0.0
    assert indicators["destination_port_diversity"] == 0.0


def test_scanning_like_traffic_has_low_syn_ack_ratio_and_many_destinations():
    window = StatisticsWindow()
    for i in range(100):
        window.update(PacketRecord("sent", f"10.0.0.{i}", 80, "S", 60, 0.0))
    window.update(PacketRecord("received", "10.0.0.1", 80, "SA", 60, 0.0))

    indicators = compute_behavioural_indicators(window)

    assert indicators["unique_destination_ips"] == 100
    assert indicators["syn_ack_ratio"] == 1 / 100
    assert indicators["connections_per_second"] == 100 / WINDOW_SIZE
    # 100 destinazioni colpite quasi uniformemente (una riceve anche il
    # SYN-ACK): diversita' molto alta, fan-out tipico di uno scan.
    assert indicators["destination_ip_diversity"] > 0.95


def test_no_syn_sent_gives_neutral_ratio_and_zero_rate():
    window = StatisticsWindow()

    indicators = compute_behavioural_indicators(window)

    assert indicators["syn_ack_ratio"] == 1.0
    assert indicators["connections_per_second"] == 0


def test_single_target_port_diversity_is_zero_when_each_destination_uses_one_port():
    window = StatisticsWindow()
    for i in range(20):
        window.update(PacketRecord("sent", f"10.0.0.{i}", 443, "S", 60, 0.0))

    indicators = compute_behavioural_indicators(window)

    assert indicators["single_target_port_diversity"] == 0.0


def test_single_target_port_diversity_is_high_for_a_port_sweep_on_one_host():
    window = StatisticsWindow()
    for port in range(20):
        window.update(PacketRecord("sent", "10.0.0.1", port, "S", 60, 0.0))

    indicators = compute_behavioural_indicators(window)

    assert indicators["single_target_port_diversity"] > 0.9


def test_single_target_port_diversity_ignores_destinations_with_too_few_packets():
    ports_by_destination = {"10.0.0.1": {80: 1, 443: 1}}

    assert compute_single_target_port_diversity(ports_by_destination) == 0.0
