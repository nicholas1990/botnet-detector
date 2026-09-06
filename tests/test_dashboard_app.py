from pathlib import Path

from streamlit.testing.v1 import AppTest

from src.analysis.behavioural import compute_behavioural_indicators
from src.analysis.statistics import StatisticsWindow
from src.capture.parser import PacketRecord
from src.reporting.persistence import save_window_result

APP_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


def _build_result():
    stats = StatisticsWindow()
    stats.update(PacketRecord("sent", "1.2.3.4", 443, "S", 60, 0.0))
    stats.update(PacketRecord("received", "1.2.3.4", 443, "SA", 60, 1.0))

    return {
        "stats": stats,
        "indicators": compute_behavioural_indicators(stats),
        "work_weight": 0.5,
        "score": 42,
        "status": "SUSPICIOUS",
        "reasons": ["test reason"],
        "window_start": 1000.0,
        "window_end": 1030.0,
    }


def _run_app_with_db(db_path):
    at = AppTest.from_file(str(APP_PATH))
    at.run(timeout=15)
    at.sidebar.text_input[0].set_value(str(db_path)).run(timeout=15)
    return at


def test_dashboard_shows_placeholder_when_no_data(tmp_path):
    at = _run_app_with_db(tmp_path / "does_not_exist.db")

    assert not at.exception
    assert any("Nessun dato" in info.value for info in at.info)


def test_dashboard_shows_latest_result_metrics(tmp_path):
    db_path = tmp_path / "dashboard.db"
    save_window_result(db_path, _build_result())

    at = _run_app_with_db(db_path)

    assert not at.exception
    metric_values = [metric.value for metric in at.metric]
    assert "42/100" in metric_values
    assert "SUSPICIOUS" in metric_values
    assert "50.0%" in metric_values
