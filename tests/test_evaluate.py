from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from evaluation.evaluate import (
    compute_metrics,
    evaluate,
    reason_key,
    replay_pcap,
    summarize_windows,
)

LOCAL_IP = "192.168.1.10"


def _packet(src, dst, sport, dport, flags, timestamp):
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    packet.time = timestamp
    return packet


def _scan_pcap(path):
    """Due finestre da 30s di SYN senza risposta verso molti host."""
    packets = [
        _packet(LOCAL_IP, f"10.0.{i // 250}.{i % 250 + 1}", 40000, 445, "S", i * 0.1)
        for i in range(600)
    ]
    wrpcap(str(path), packets)


def _window(score, status, reasons=()):
    return {"score": score, "status": status, "reasons": list(reasons)}


def test_reason_key_strips_numeric_value():
    assert reason_key("High Work Weight (80%)") == "High Work Weight"
    assert reason_key("Low SYN/SYN-ACK response ratio") == "Low SYN/SYN-ACK response ratio"
    assert (
        reason_key("Periodic beaconing pattern detected, regularity index 0.88")
        == "Periodic beaconing pattern detected"
    )


def test_summarize_windows_counts_alerts_and_reasons():
    summary = summarize_windows([
        _window(10, "NORMAL"),
        _window(40, "SUSPICIOUS", ["High Work Weight (60%)"]),
        _window(90, "HIGH RISK", ["High Work Weight (95%)", "Large number of destination IPs (80)"]),
    ])

    assert summary["windows"] == 3
    assert summary["alert_rate"] == 2 / 3
    assert summary["score_max"] == 90
    assert summary["reasons"] == {"High Work Weight": 2, "Large number of destination IPs": 1}


def test_summarize_windows_handles_empty_capture():
    summary = summarize_windows([])

    assert summary["windows"] == 0
    assert summary["alert_rate"] == 0.0


def test_compute_metrics_weights_datasets_by_window_count():
    metrics = compute_metrics({
        "botnet": [
            {"windows": 10, "alert_rate": 1.0},
            {"windows": 30, "alert_rate": 0.0},
        ],
        "normal": [{"windows": 50, "alert_rate": 0.1}],
    })

    assert metrics["detection_rate"] == 0.25
    assert metrics["false_positive_rate"] == 0.1


def test_replay_pcap_runs_detector_offline(tmp_path):
    pcap = tmp_path / "scan.pcap"
    _scan_pcap(pcap)

    windows = replay_pcap(pcap, LOCAL_IP, window_size=30)

    assert len(windows) == 2
    assert all(w["status"] == "HIGH RISK" for w in windows)


def test_evaluate_skips_missing_pcaps_and_labels_results(tmp_path):
    _scan_pcap(tmp_path / "scan.pcap")
    datasets = [
        {"name": "scan", "pcap": "scan.pcap", "local_ip": LOCAL_IP, "label": "botnet"},
        {"name": "missing", "pcap": "missing.pcap", "local_ip": LOCAL_IP, "label": "normal"},
    ]

    report = evaluate(datasets, window_size=30, base_dir=tmp_path)

    assert [d["name"] for d in report["datasets"]] == ["scan"]
    assert report["metrics"]["detection_rate"] == 1.0
    assert "false_positive_rate" not in report["metrics"]


def test_compute_metrics_reports_capture_level_rates_excluding_empty_captures():
    metrics = compute_metrics({
        "botnet": [
            {"windows": 10, "alert_rate": 0.1},
            {"windows": 5, "alert_rate": 0.0},
            {"windows": 0, "alert_rate": 0.0},
        ],
        "normal": [
            {"windows": 20, "alert_rate": 0.0},
            {"windows": 20, "alert_rate": 0.05},
        ],
    })

    assert metrics["botnet"]["captures"] == 3
    assert metrics["botnet"]["captures_with_traffic"] == 2
    assert metrics["capture_detection_rate"] == 0.5
    assert metrics["capture_false_positive_rate"] == 0.5


def test_evaluate_reports_metrics_per_split(tmp_path):
    _scan_pcap(tmp_path / "scan.pcap")
    datasets = [
        {"name": "tuned", "pcap": "scan.pcap", "local_ip": LOCAL_IP, "label": "botnet", "split": "tuning"},
        {"name": "fresh", "pcap": "scan.pcap", "local_ip": LOCAL_IP, "label": "botnet"},
    ]

    report = evaluate(datasets, window_size=30, base_dir=tmp_path)

    assert set(report["metrics_by_split"]) == {"tuning", "holdout"}
    assert report["metrics_by_split"]["holdout"]["botnet"]["captures"] == 1
    assert report["metrics"]["botnet"]["captures"] == 2


def test_evaluate_in_parallel_matches_sequential(tmp_path):
    _scan_pcap(tmp_path / "scan.pcap")
    datasets = [
        {"name": f"scan-{i}", "pcap": "scan.pcap", "local_ip": LOCAL_IP, "label": "botnet"}
        for i in range(2)
    ]

    sequential = evaluate(datasets, window_size=30, base_dir=tmp_path)
    parallel = evaluate(datasets, window_size=30, base_dir=tmp_path, jobs=2)

    assert parallel["datasets"] == sequential["datasets"]
