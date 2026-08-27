from src.analysis.statistics import StatisticsWindow


def test_statistics_window_starts_empty():
    window = StatisticsWindow()
    assert window.syn_sent == 0
    assert window.unique_destination_ips == set()
