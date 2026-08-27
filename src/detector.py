"""Orchestrazione: cattura -> parsing -> statistiche -> scoring -> alert."""

from src.analysis.statistics import StatisticsWindow
from src.analysis.work_weight import compute_work_weight
from src.capture.parser import parse_packet
from src.capture.sniffer import start_capture
from src.config import WINDOW_SIZE
from src.scoring.risk_score import compute_risk_score


class Detector:
    def __init__(self, local_ip, interface=None, window_size=WINDOW_SIZE, on_window_complete=None):
        self.local_ip = local_ip
        self.interface = interface
        self.window_size = window_size
        self.on_window_complete = on_window_complete
        self.window = StatisticsWindow()
        self.window_start = None

    def process_packet(self, packet):
        record = parse_packet(packet, self.local_ip)
        if record is None:
            return

        if self.window_start is None:
            self.window_start = record.timestamp
        elif record.timestamp - self.window_start >= self.window_size:
            self._close_window()
            self.window_start = record.timestamp

        self.window.update(record)

    def _close_window(self):
        total_tcp_packets = self.window.packets_sent + self.window.packets_received
        work_weight = compute_work_weight(
            syn_sent=self.window.syn_sent,
            fin_sent=self.window.fin_sent,
            rst_received=self.window.rst_received,
            total_tcp_packets=total_tcp_packets,
        )
        result = compute_risk_score(self.window, work_weight)
        result["work_weight"] = work_weight
        result["stats"] = self.window
        result["window_start"] = self.window_start
        result["window_end"] = self.window_start + self.window_size

        if self.on_window_complete:
            self.on_window_complete(result)

        self.window = StatisticsWindow()

    def run(self):
        try:
            start_capture(interface=self.interface, packet_callback=self.process_packet)
        finally:
            if self.window.packets_sent or self.window.packets_received:
                self._close_window()
