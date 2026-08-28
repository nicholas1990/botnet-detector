"""Verifica end-to-end sul dataset di test controllato (specifiche sez. 14)."""

from src.analysis.statistics import StatisticsWindow
from src.analysis.work_weight import compute_work_weight
from src.scoring.risk_score import compute_risk_score
from tests.fixtures.scenarios import (
    scenario_a_normal_traffic,
    scenario_b_many_connections,
    scenario_c_scanning,
)


def _score_for(records):
    stats = StatisticsWindow()
    for record in records:
        stats.update(record)

    total_tcp_packets = stats.packets_sent + stats.packets_received
    work_weight = compute_work_weight(
        syn_sent=stats.syn_sent,
        fin_sent=stats.fin_sent,
        rst_received=stats.rst_received,
        total_tcp_packets=total_tcp_packets,
    )
    return compute_risk_score(stats, work_weight)


def test_scenario_a_normal_traffic_is_low_risk():
    result = _score_for(scenario_a_normal_traffic())

    assert result["status"] == "NORMAL"
    assert result["reasons"] == []


def test_scenario_c_scanning_is_high_risk():
    result = _score_for(scenario_c_scanning())

    assert result["status"] == "HIGH RISK"
    assert result["reasons"] != []


def test_scanning_scores_higher_than_normal_and_many_connections():
    score_a = _score_for(scenario_a_normal_traffic())["score"]
    score_b = _score_for(scenario_b_many_connections())["score"]
    score_c = _score_for(scenario_c_scanning())["score"]

    assert score_a < score_b < score_c
