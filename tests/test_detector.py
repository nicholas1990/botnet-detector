import time
from unittest.mock import patch

from scapy.layers.inet import IP, TCP

from src.detector import Detector
from src.whitelist import Whitelist, WhitelistEntry

LOCAL_IP = "192.168.1.10"
REMOTE_IP = "203.0.113.5"


def _tcp_packet(src, dst, sport, dport, flags, timestamp):
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    packet.time = timestamp
    return packet


def test_process_packet_accumulates_stats_within_window():
    detector = Detector(local_ip=LOCAL_IP, window_size=30)

    detector.process_packet(_tcp_packet(LOCAL_IP, REMOTE_IP, 1, 443, "S", 0.0))
    detector.process_packet(_tcp_packet(REMOTE_IP, LOCAL_IP, 443, 1, "SA", 1.0))

    assert detector.window.syn_sent == 1
    assert detector.window.syn_ack_received == 1
    assert detector.window.packets_sent == 1
    assert detector.window.packets_received == 1


def test_process_packet_ignores_unrelated_traffic():
    detector = Detector(local_ip=LOCAL_IP, window_size=30)

    detector.process_packet(_tcp_packet("10.0.0.1", "10.0.0.2", 1, 2, "S", 0.0))

    assert detector.window.packets_sent == 0
    assert detector.window.packets_received == 0


def test_window_closes_and_reports_result_after_window_size_elapsed():
    results = []
    detector = Detector(
        local_ip=LOCAL_IP, window_size=30, on_window_complete=results.append
    )

    detector.process_packet(_tcp_packet(LOCAL_IP, REMOTE_IP, 1, 443, "S", 0.0))
    detector.process_packet(_tcp_packet(LOCAL_IP, REMOTE_IP, 1, 443, "S", 10.0))
    # questo pacchetto è fuori dalla prima finestra di 30s -> la chiude
    detector.process_packet(_tcp_packet(LOCAL_IP, REMOTE_IP, 1, 443, "S", 31.0))

    assert len(results) == 1
    closed_window_result = results[0]
    assert closed_window_result["stats"].syn_sent == 2
    assert closed_window_result["work_weight"] == 1.0
    assert "score" in closed_window_result
    assert "status" in closed_window_result

    # il pacchetto che ha innescato la rotazione inizia ad accumulare la nuova finestra
    assert detector.window.syn_sent == 1


def test_whitelisted_traffic_is_excluded_from_statistics():
    whitelist = Whitelist(
        [WhitelistEntry(ip=REMOTE_IP, port=443, service="test", added_at=time.time(), ttl_days=30)]
    )
    detector = Detector(local_ip=LOCAL_IP, window_size=30, whitelist=whitelist)

    detector.process_packet(_tcp_packet(LOCAL_IP, REMOTE_IP, 1, 443, "S", 0.0))

    assert detector.window.packets_sent == 0
    assert detector.window.syn_sent == 0


def test_run_delegates_to_start_capture_and_closes_final_window():
    detector = Detector(local_ip=LOCAL_IP, interface="eth0")

    def fake_start_capture(interface, packet_callback):
        packet_callback(_tcp_packet(LOCAL_IP, REMOTE_IP, 1, 443, "S", 0.0))

    with patch("src.detector.start_capture", side_effect=fake_start_capture) as mock_start:
        with patch.object(detector, "_close_window") as mock_close:
            detector.run()

    mock_start.assert_called_once_with(interface="eth0", packet_callback=detector.process_packet)
    mock_close.assert_called_once()
