from src.analysis.statistics import StatisticsWindow
from src.capture.parser import PacketRecord


def test_statistics_window_starts_empty():
    window = StatisticsWindow()
    assert window.syn_sent == 0
    assert len(window.unique_destination_ips) == 0


def test_update_counts_syn_sent():
    window = StatisticsWindow()
    window.update(PacketRecord("sent", "10.0.0.1", 80, "S", 60, 0.0))
    assert window.syn_sent == 1
    assert window.packets_sent == 1
    assert window.bytes_sent == 60
    assert window.unique_destination_ips == {"10.0.0.1": 1}
    assert window.unique_destination_ports == {80: 1}


def test_update_counts_syn_ack_received():
    window = StatisticsWindow()
    window.update(PacketRecord("received", "10.0.0.1", 80, "SA", 60, 0.0))
    assert window.syn_ack_received == 1
    assert window.syn_sent == 0
    assert window.packets_received == 1


def test_update_counts_fin_sent_and_rst_received():
    window = StatisticsWindow()
    window.update(PacketRecord("sent", "10.0.0.2", 443, "F", 40, 0.0))
    window.update(PacketRecord("received", "10.0.0.3", 22, "R", 40, 0.0))
    assert window.fin_sent == 1
    assert window.rst_received == 1
    assert window.unique_destination_ips == {"10.0.0.2": 1, "10.0.0.3": 1}
    assert window.unique_destination_ports == {443: 1, 22: 1}
