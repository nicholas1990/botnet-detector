"""Raccolta statistiche TCP per finestra temporale."""

from collections import Counter, defaultdict


class StatisticsWindow:
    def __init__(self):
        self.syn_sent = 0
        self.syn_ack_received = 0
        self.fin_sent = 0
        self.rst_received = 0
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        # Counter invece di set: len() da' comunque il numero di destinazioni
        # distinte, ma le frequenze servono anche per il Simpson Diversity
        # Index (vedi src/analysis/diversity.py).
        self.unique_destination_ips = Counter()
        self.unique_destination_ports = Counter()
        # Porte per singola destinazione (DDP per-coppia, specifiche sez. 4/6):
        # serve a distinguere "molte destinazioni, stessa porta ciascuna"
        # (normale) da "una destinazione sondata su molte porte" (port sweep).
        self.ports_by_destination = defaultdict(Counter)
        # Timestamp dei SYN inviati per destinazione (Time Between Flows,
        # specifiche sez. 4-5): serve a misurare la regolarita' degli
        # intervalli tra flow consecutivi verso lo stesso host.
        self.syn_timestamps_by_destination = defaultdict(list)

    def update(self, record):
        if record.direction == "sent":
            self.packets_sent += 1
            self.bytes_sent += record.size
            if "S" in record.flags and "A" not in record.flags:
                self.syn_sent += 1
                self.syn_timestamps_by_destination[record.remote_ip].append(record.timestamp)
            if "F" in record.flags:
                self.fin_sent += 1
        else:
            self.packets_received += 1
            self.bytes_received += record.size
            if "S" in record.flags and "A" in record.flags:
                self.syn_ack_received += 1
            if "R" in record.flags:
                self.rst_received += 1

        self.unique_destination_ips[record.remote_ip] += 1
        self.unique_destination_ports[record.remote_port] += 1
        self.ports_by_destination[record.remote_ip][record.remote_port] += 1
