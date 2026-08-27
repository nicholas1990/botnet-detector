from src.analysis.behavioural import compute_behavioural_indicators
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


def test_scanning_like_traffic_has_low_syn_ack_ratio_and_many_destinations():
    window = StatisticsWindow()
    for i in range(100):
        window.update(PacketRecord("sent", f"10.0.0.{i}", 80, "S", 60, 0.0))
    window.update(PacketRecord("received", "10.0.0.1", 80, "SA", 60, 0.0))

    indicators = compute_behavioural_indicators(window)

    assert indicators["unique_destination_ips"] == 100
    assert indicators["syn_ack_ratio"] == 1 / 100
    assert indicators["connections_per_second"] == 100 / WINDOW_SIZE


def test_no_syn_sent_gives_neutral_ratio_and_zero_rate():
    window = StatisticsWindow()

    indicators = compute_behavioural_indicators(window)

    assert indicators["syn_ack_ratio"] == 1.0
    assert indicators["connections_per_second"] == 0
