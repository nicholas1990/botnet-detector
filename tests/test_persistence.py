from src.analysis.behavioural import compute_behavioural_indicators
from src.analysis.statistics import StatisticsWindow
from src.capture.parser import PacketRecord
from src.reporting.persistence import fetch_recent_results, save_window_result


def _build_result(window_start, score=82, status="HIGH RISK"):
    stats = StatisticsWindow()
    stats.update(PacketRecord("sent", "1.2.3.4", 443, "S", 60, window_start))
    stats.update(PacketRecord("received", "1.2.3.4", 443, "SA", 60, window_start + 1))
    stats.update(PacketRecord("sent", "5.6.7.8", 22, "S", 60, window_start + 2))

    return {
        "stats": stats,
        "indicators": compute_behavioural_indicators(stats),
        "work_weight": 0.787,
        "score": score,
        "status": status,
        "reasons": ["High Work Weight (78.7%)"],
        "window_start": window_start,
        "window_end": window_start + 30,
    }


def test_save_and_fetch_round_trips_a_result(tmp_path):
    db_path = tmp_path / "dashboard.db"
    result = _build_result(window_start=1000.0)

    save_window_result(db_path, result)
    fetched = fetch_recent_results(db_path)

    assert len(fetched) == 1
    entry = fetched[0]
    assert entry["window_start"] == 1000.0
    assert entry["window_end"] == 1030.0
    assert entry["score"] == 82
    assert entry["status"] == "HIGH RISK"
    assert entry["tcp_packets"] == 3
    assert entry["syn_sent"] == 2
    assert entry["syn_ack_received"] == 1
    assert entry["unique_destination_ips"] == 2
    assert entry["unique_destination_ports"] == 2
    assert entry["reasons"] == ["High Work Weight (78.7%)"]
    assert entry["indicators"] == compute_behavioural_indicators(result["stats"])


def test_fetch_recent_results_orders_newest_first_and_respects_limit(tmp_path):
    db_path = tmp_path / "dashboard.db"

    for window_start in (1000.0, 1030.0, 1060.0):
        save_window_result(db_path, _build_result(window_start))

    fetched = fetch_recent_results(db_path, limit=2)

    assert [entry["window_start"] for entry in fetched] == [1060.0, 1030.0]


def test_fetch_recent_results_returns_empty_list_for_new_database(tmp_path):
    db_path = tmp_path / "does_not_exist_yet.db"

    assert fetch_recent_results(db_path) == []
