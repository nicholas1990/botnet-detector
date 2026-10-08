"""Time Between Flows (TBF): binning a 100 ms (specifiche sez. 4-5)."""

from src.config import TBF_MERGE_GAP_SECONDS

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


def group_flow_events(timestamps, merge_gap_seconds=TBF_MERGE_GAP_SECONDS):
    """Fonde i SYN ravvicinati in eventi: un SYN a meno di `merge_gap_seconds`
    dal precedente appartiene allo stesso evento (connessioni parallele,
    burst). Restituisce il timestamp di inizio di ciascun evento."""
    ordered = sorted(timestamps)
    events = ordered[:1]
    for previous, current in zip(ordered, ordered[1:]):
        if current - previous >= merge_gap_seconds:
            events.append(current)
    return events
