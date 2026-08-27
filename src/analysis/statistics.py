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
        if record.direction == "sent":
            self.packets_sent += 1
            self.bytes_sent += record.size
            if "S" in record.flags and "A" not in record.flags:
                self.syn_sent += 1
            if "F" in record.flags:
                self.fin_sent += 1
        else:
            self.packets_received += 1
            self.bytes_received += record.size
            if "S" in record.flags and "A" in record.flags:
                self.syn_ack_received += 1
            if "R" in record.flags:
                self.rst_received += 1

        self.unique_destination_ips.add(record.remote_ip)
        self.unique_destination_ports.add(record.remote_port)
