from src.analysis.history import DestinationHistory, is_regular_series
from src.capture.parser import PacketRecord
from src.config import LONG_BEACONING_MAX_PERIOD_SECONDS, LONG_BEACONING_MIN_EVENTS

C2 = ("198.51.100.7", 443)


def _record(timestamp, flags="S", size=60, direction="sent", destination=C2):
    return PacketRecord(
        direction=direction,
        remote_ip=destination[0],
        remote_port=destination[1],
        flags=flags,
        size=size,
        timestamp=timestamp,
    )


def _beacon(history, start, request_size=300, destination=C2):
    history.update(_record(start, destination=destination))
    history.update(_record(start + 0.1, flags="SA", direction="received", destination=destination))
    history.update(_record(start + 0.2, flags="PA", size=request_size, destination=destination))


def test_regular_series_requires_plausible_period_and_similar_size():
    regular = [(i * 120.0, 400) for i in range(LONG_BEACONING_MIN_EVENTS)]
    assert is_regular_series(regular)
    assert not is_regular_series([(i * 2.0, 400) for i in range(LONG_BEACONING_MIN_EVENTS)])
    assert not is_regular_series([(t, 400 if i % 2 else 4000) for i, (t, _) in enumerate(regular)])
    jittered = [(t + (60 if i % 2 else 0), size) for i, (t, size) in enumerate(regular)]
    assert not is_regular_series(jittered)


def test_beacon_every_two_minutes_is_flagged_once_enough_events_are_seen():
    history = DestinationHistory()
    flagged = []
    for i in range(LONG_BEACONING_MIN_EVENTS):
        _beacon(history, i * 120.0)
        flagged.append(history.close_window(i * 120.0 + 30))

    assert flagged[:-1] == [[]] * (LONG_BEACONING_MIN_EVENTS - 1)
    assert flagged[-1] == [C2]


def test_parallel_connections_count_as_one_event():
    history = DestinationHistory()
    for i in range(LONG_BEACONING_MIN_EVENTS):
        _beacon(history, i * 120.0)
        _beacon(history, i * 120.0 + 0.3)

    assert history.close_window(LONG_BEACONING_MIN_EVENTS * 120.0) == [C2]


def test_irregular_browsing_is_not_flagged():
    history = DestinationHistory()
    for i, start in enumerate([0, 40, 400, 410, 1300, 1700, 1720, 3000, 3100]):
        _beacon(history, float(start), request_size=300 + 97 * i)

    assert history.close_window(3130.0) == []


def test_destinations_silent_longer_than_max_period_are_forgotten():
    history = DestinationHistory()
    _beacon(history, 0.0)
    _beacon(history, 10.0, destination=("203.0.113.9", 80))

    history.close_window(LONG_BEACONING_MAX_PERIOD_SECONDS + 5.0)

    assert list(history._events) == [("203.0.113.9", 80)]
    history.close_window(LONG_BEACONING_MAX_PERIOD_SECONDS + 15.0)
    assert not history._events
