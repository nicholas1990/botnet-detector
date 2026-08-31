from src.analysis.statistics import StatisticsWindow
from src.analysis.work_weight import compute_work_weight
from src.capture.parser import PacketRecord
from src.config import RISK_THRESHOLD_HIGH, RISK_THRESHOLD_SUSPICIOUS
from src.scoring.risk_score import compute_risk_score


def _work_weight_for(window):
    total = window.packets_sent + window.packets_received
    return compute_work_weight(
        window.syn_sent, window.fin_sent, window.rst_received, total
    )


def test_normal_traffic_gets_low_score_and_normal_status():
    window = StatisticsWindow()
    window.update(PacketRecord("sent", "1.2.3.4", 443, "S", 60, 0.0))
    window.update(PacketRecord("received", "1.2.3.4", 443, "SA", 60, 0.0))
    for _ in range(17):
        window.update(PacketRecord("sent", "1.2.3.4", 443, "PA", 200, 0.0))
    window.update(PacketRecord("sent", "1.2.3.4", 443, "F", 0, 0.0))

    result = compute_risk_score(window, _work_weight_for(window))

    assert result["score"] < RISK_THRESHOLD_SUSPICIOUS
    assert result["status"] == "NORMAL"
    assert result["reasons"] == []


def test_scanning_like_traffic_gets_high_score_and_high_risk_status():
    window = StatisticsWindow()
    for i in range(100):
        window.update(PacketRecord("sent", f"10.0.0.{i}", 80, "S", 60, 0.0))
    window.update(PacketRecord("received", "10.0.0.1", 80, "SA", 60, 0.0))

    result = compute_risk_score(window, _work_weight_for(window))

    assert result["score"] >= RISK_THRESHOLD_HIGH
    assert result["status"] == "HIGH RISK"
    assert any("Work Weight" in reason for reason in result["reasons"])
    assert any("destination IPs" in reason for reason in result["reasons"])


def test_diversity_bonus_is_ignored_with_too_few_packets():
    window = StatisticsWindow()
    window.update(PacketRecord("sent", "1.2.3.4", 443, "S", 60, 0.0))
    window.update(PacketRecord("sent", "5.6.7.8", 22, "S", 60, 0.0))

    result = compute_risk_score(window, _work_weight_for(window))

    assert not any("diversity" in reason.lower() for reason in result["reasons"])


def test_evenly_spread_destinations_add_diversity_reason():
    window = StatisticsWindow()
    for i in range(10):
        window.update(PacketRecord("sent", f"10.0.0.{i}", 80, "S", 60, 0.0))

    result = compute_risk_score(window, _work_weight_for(window))

    assert any("diversity" in reason.lower() for reason in result["reasons"])


def test_port_sweep_on_single_host_adds_port_sweep_reason():
    window = StatisticsWindow()
    for port in range(20):
        window.update(PacketRecord("sent", "10.0.0.1", port, "S", 60, 0.0))

    result = compute_risk_score(window, _work_weight_for(window))

    assert any("Port sweep" in reason for reason in result["reasons"])


def test_score_is_capped_at_100():
    window = StatisticsWindow()
    for i in range(200):
        window.update(PacketRecord("sent", f"10.0.{i // 256}.{i % 256}", i, "S", 60, 0.0))

    result = compute_risk_score(window, work_weight=1.0)

    assert result["score"] <= 100
