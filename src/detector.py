"""Orchestrazione: cattura -> parsing -> statistiche -> scoring -> alert."""

from src.analysis.history import DestinationHistory
from src.analysis.statistics import StatisticsWindow
from src.analysis.work_weight import compute_work_weight
from src.capture.parser import parse_packet
from src.capture.sniffer import start_capture
from src.config import WHITELIST_PATH, WINDOW_SIZE
from src.scoring.risk_score import compute_risk_score
from src.filtering.whitelist import load_whitelist


class Detector:
    def __init__(
        self,
        local_ip,
        interface=None,
        window_size=WINDOW_SIZE,
        on_window_complete=None,
        whitelist=None,
        pcap_path=None,
    ):
        self.local_ip = local_ip
        self.interface = interface
        self.pcap_path = pcap_path
        self.window_size = window_size
        self.on_window_complete = on_window_complete
        self.whitelist = whitelist if whitelist is not None else load_whitelist(WHITELIST_PATH)
        self.window = StatisticsWindow()
        self.window_start = None
        # Sopravvive alla chiusura delle finestre: vedi src/analysis/history.py.
        self.history = DestinationHistory()

    def process_packet(self, packet):
        record = parse_packet(packet, self.local_ip)
        if record is None:
            return

        if self.whitelist.is_whitelisted(record.remote_ip, record.remote_port):
            return

        if self.window_start is None:
            self.window_start = record.timestamp
        elif record.timestamp - self.window_start >= self.window_size:
            self._close_window()
            self.window_start = record.timestamp

        self.window.update(record)
        self.history.update(record)

    def _close_window(self):
        total_tcp_packets = self.window.packets_sent + self.window.packets_received
        work_weight = compute_work_weight(
            syn_sent=self.window.syn_sent,
            fin_sent=self.window.fin_sent,
            rst_received=self.window.rst_received,
            total_tcp_packets=total_tcp_packets,
        )
        window_end = self.window_start + self.window_size
        periodic_destinations = self.history.close_window(window_end)
        result = compute_risk_score(self.window, work_weight, periodic_destinations)
        result["work_weight"] = work_weight
        result["stats"] = self.window
        result["window_start"] = self.window_start
        result["window_end"] = window_end

        if self.on_window_complete:
            self.on_window_complete(result)

        self.window = StatisticsWindow()

    def run(self):
        try:
            start_capture(
                interface=self.interface,
                packet_callback=self.process_packet,
                pcap_path=self.pcap_path,
            )
        finally:
            if self.window.packets_sent or self.window.packets_received:
                self._close_window()
