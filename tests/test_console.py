import time

from src.analysis.statistics import StatisticsWindow
from src.capture.parser import PacketRecord
from src.reporting.console import format_window_report


def _build_result():
    stats = StatisticsWindow()
    stats.update(PacketRecord("sent", "1.2.3.4", 443, "S", 60, 0.0))
    stats.update(PacketRecord("received", "1.2.3.4", 443, "SA", 60, 1.0))
    stats.update(PacketRecord("sent", "5.6.7.8", 22, "S", 60, 2.0))

    return {
        "stats": stats,
        "work_weight": 0.787,
        "score": 82,
        "status": "HIGH RISK",
        "reasons": ["High Work Weight (78.7%)", "Large number of destination IPs (421)"],
        "window_start": 1000.0,
        "window_end": 1030.0,
    }


def test_format_window_report_contains_expected_sections():
    report = format_window_report(_build_result())

    expected_start = time.strftime("%H:%M:%S", time.localtime(1000.0))
    expected_end = time.strftime("%H:%M:%S", time.localtime(1030.0))

    assert "HOST NETWORK MONITOR" in report
    assert f"Window: {expected_start} - {expected_end}" in report
    assert "TCP packets:          3" in report
    assert "SYN sent:             2" in report
    assert "SYN-ACK received:     1" in report
    assert "FIN sent:             0" in report
    assert "RST received:         0" in report
    assert "Unique destination IP: 2" in report
    assert "Unique destination port: 2" in report
    assert "TCP Work Weight:      78.7%" in report
    assert "Risk Score:           82/100" in report
    assert "STATUS: HIGH RISK" in report
    assert "[!] High Work Weight (78.7%)" in report
    assert "[!] Large number of destination IPs (421)" in report


def test_format_window_report_omits_reasons_section_when_no_reasons():
    result = _build_result()
    result["reasons"] = []

    report = format_window_report(result)

    assert "Reasons:" not in report
