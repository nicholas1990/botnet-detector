"""Verifica end-to-end sul dataset di test controllato (specifiche sez. 14)."""

import time

from src.analysis.statistics import StatisticsWindow
from src.analysis.work_weight import compute_work_weight
from src.filtering.whitelist import Whitelist, WhitelistEntry
from src.scoring.risk_score import compute_risk_score
from tests.fixtures.scenarios import (
    scenario_a_normal_traffic,
    scenario_b_many_connections,
    scenario_c_scanning,
    scenario_d_beaconing_and_port_sweep,
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


def test_scenario_d_combined_beaconing_and_port_sweep_is_high_risk_with_both_reasons():
    """Le due anomalie indipendenti (beaconing su un host, port sweep su un
    altro) devono essere rilevate entrambe nella stessa finestra, non solo
    la più marcata delle due."""
    result = _score_for(scenario_d_beaconing_and_port_sweep())

    assert result["status"] == "HIGH RISK"
    assert any("beaconing" in reason.lower() for reason in result["reasons"])
    assert any("port sweep" in reason.lower() for reason in result["reasons"])


def test_scenario_c_scanning_scores_normal_when_fully_whitelisted():
    """Traffico che da solo sarebbe HIGH RISK (scenario C) non deve generare
    nessun alert se le porte sondate sono interamente whitelisted: il
    filtro in Detector.process_packet esclude i pacchetti a monte, prima
    che entrino nelle statistiche."""
    whitelist = Whitelist(
        [
            WhitelistEntry(ip=None, port=445, service="test", added_at=time.time()),
            WhitelistEntry(ip=None, port=3389, service="test", added_at=time.time()),
        ]
    )
    records = [
        record
        for record in scenario_c_scanning()
        if not whitelist.is_whitelisted(record.remote_ip, record.remote_port)
    ]

    result = _score_for(records)

    assert result["status"] == "NORMAL"
    assert result["reasons"] == []
