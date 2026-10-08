from unittest.mock import patch

from src.capture.sniffer import start_capture


def test_start_capture_sniffs_tcp_on_given_interface():
    callback = object()

    with patch("src.capture.sniffer.sniff") as mock_sniff:
        start_capture(interface="eth0", packet_callback=callback)

    mock_sniff.assert_called_once_with(
        iface="eth0", filter="tcp", prn=callback, store=False
    )


def test_start_capture_defaults_to_no_specific_interface():
    with patch("src.capture.sniffer.sniff") as mock_sniff:
        start_capture()

    mock_sniff.assert_called_once_with(
        iface=None, filter="tcp", prn=None, store=False
    )


def test_start_capture_reads_pcap_offline_without_bpf_filter():
    callback = object()

    with patch("src.capture.sniffer.sniff") as mock_sniff:
        start_capture(packet_callback=callback, pcap_path="capture.pcap")

    mock_sniff.assert_called_once_with(
        offline="capture.pcap", prn=callback, store=False
    )
