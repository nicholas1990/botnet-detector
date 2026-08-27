"""Raccolta statistiche TCP per finestra temporale."""


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
        self.unique_destination_ips = set()
        self.unique_destination_ports = set()

    def update(self, record):
        raise NotImplementedError
