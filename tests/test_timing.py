from src.analysis.timing import bin_ms, group_flow_events, inter_arrival_bins_ms


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


def test_group_flow_events_merges_syns_closer_than_gap():
    # Burst di 3 connessioni parallele a t=0, poi un SYN isolato a t=10.
    assert group_flow_events([0.0, 0.01, 0.02, 10.0], merge_gap_seconds=1.0) == [0.0, 10.0]


def test_group_flow_events_chains_gap_from_previous_syn():
    # Ogni SYN dista meno di 1s dal precedente: un unico evento anche se il
    # burst complessivo dura più di 1s.
    assert group_flow_events([0.0, 0.8, 1.6, 2.4], merge_gap_seconds=1.0) == [0.0]


def test_group_flow_events_keeps_spaced_syns_and_sorts():
    assert group_flow_events([20.0, 0.0, 10.0], merge_gap_seconds=1.0) == [0.0, 10.0, 20.0]
    assert group_flow_events([]) == []
