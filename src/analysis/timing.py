"""Time Between Flows (TBF): binning a 100 ms (specifiche sez. 4-5)."""

TBF_BIN_MS = 100


def bin_ms(value_ms, bin_size_ms=TBF_BIN_MS):
    return int(value_ms // bin_size_ms) * bin_size_ms


def inter_arrival_bins_ms(timestamps, bin_size_ms=TBF_BIN_MS):
    """Delta (ms) tra flow consecutivi, ordinati per timestamp e binnati."""
    ordered = sorted(timestamps)
    return [
        bin_ms((later - earlier) * 1000, bin_size_ms)
        for earlier, later in zip(ordered, ordered[1:])
    ]
