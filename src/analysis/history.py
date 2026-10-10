"""Memoria tra finestre: beaconing a lungo periodo verso la stessa destinazione.

Gli indicatori per finestra vedono solo 30s di traffico: un bot che contatta
il C&C ogni pochi minuti con connessioni riuscite produce finestre con un
solo flow, indistinguibili dal traffico normale. Qui si ricordano, per ogni
coppia (IP, porta), gli ultimi eventi di connessione e si segnala la
destinazione quando formano una serie regolare per periodo e dimensione.
"""

import statistics
from collections import OrderedDict, deque

from src.config import (
    LONG_BEACONING_MAX_BYTES_CV,
    LONG_BEACONING_MAX_INTERVAL_CV,
    LONG_BEACONING_MAX_PERIOD_SECONDS,
    LONG_BEACONING_MAX_TRACKED_DESTINATIONS,
    LONG_BEACONING_MIN_EVENTS,
    LONG_BEACONING_MIN_PERIOD_SECONDS,
    TBF_MERGE_GAP_SECONDS,
)


def _coefficient_of_variation(values):
    mean = statistics.mean(values)
    if mean <= 0:
        return None
    return statistics.pstdev(values) / mean


def is_regular_series(events):
    """`events`: lista di (inizio, byte inviati). Vero se gli intervalli tra
    inizi consecutivi hanno periodo plausibile per un C&C e sono regolari, e
    ogni evento invia circa gli stessi byte (stessa richiesta ripetuta)."""
    starts = [start for start, _ in events]
    intervals = [later - earlier for earlier, later in zip(starts, starts[1:])]
    period = statistics.mean(intervals)
    if not LONG_BEACONING_MIN_PERIOD_SECONDS <= period <= LONG_BEACONING_MAX_PERIOD_SECONDS:
        return False
    if statistics.pstdev(intervals) / period > LONG_BEACONING_MAX_INTERVAL_CV:
        return False
    bytes_cv = _coefficient_of_variation([sent for _, sent in events])
    return bytes_cv is not None and bytes_cv <= LONG_BEACONING_MAX_BYTES_CV


class DestinationHistory:
    """Eventi di connessione in uscita per (IP, porta), conservati tra le
    finestre. Un evento inizia con un SYN inviato ad almeno
    TBF_MERGE_GAP_SECONDS dall'inizio dell'evento precedente verso la stessa
    coppia (connessioni parallele = un solo evento) e accumula i byte inviati
    fino al successivo."""

    def __init__(self):
        self._events = OrderedDict()
        self._started_in_window = set()

    def update(self, record):
        if record.direction != "sent":
            return
        key = (record.remote_ip, record.remote_port)
        events = self._events.get(key)
        is_syn = "S" in record.flags and "A" not in record.flags
        if is_syn and (not events or record.timestamp - events[-1][0] >= TBF_MERGE_GAP_SECONDS):
            if events is None:
                events = self._events[key] = deque(maxlen=LONG_BEACONING_MIN_EVENTS)
            self._events.move_to_end(key)
            events.append([record.timestamp, 0])
            self._started_in_window.add(key)
            if len(self._events) > LONG_BEACONING_MAX_TRACKED_DESTINATIONS:
                self._events.popitem(last=False)
        if events:
            events[-1][1] += record.size

    def close_window(self, window_end):
        """Destinazioni la cui serie regolare si è completata con un evento
        iniziato in questa finestra; dimentica quelle silenziose da più del
        periodo massimo, la cui serie è comunque interrotta."""
        periodic = [
            key
            for key in self._started_in_window
            if key in self._events
            and len(self._events[key]) == LONG_BEACONING_MIN_EVENTS
            and is_regular_series(self._events[key])
        ]
        self._started_in_window = set()
        while self._events:
            key, events = next(iter(self._events.items()))
            if window_end - events[-1][0] <= LONG_BEACONING_MAX_PERIOD_SECONDS:
                break
            del self._events[key]
        return sorted(periodic)
