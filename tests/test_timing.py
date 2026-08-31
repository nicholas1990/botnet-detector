from src.analysis.timing import bin_ms, inter_arrival_bins_ms


def test_bin_ms_rounds_down_to_nearest_bin():
    assert bin_ms(0) == 0
    assert bin_ms(99) == 0
    assert bin_ms(100) == 100
    assert bin_ms(249) == 200


def test_inter_arrival_bins_ms_sorts_and_computes_deltas():
    # 0.0s, 0.05s, 0.2s -> delta 50ms (bin 0), 150ms (bin 100)
    assert inter_arrival_bins_ms([0.2, 0.0, 0.05]) == [0, 100]


def test_inter_arrival_bins_ms_needs_at_least_two_timestamps():
    assert inter_arrival_bins_ms([1.0]) == []
    assert inter_arrival_bins_ms([]) == []
