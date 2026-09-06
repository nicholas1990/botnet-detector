import time
from pathlib import Path

from streamlit.testing.v1 import AppTest

from dashboard.app import HISTORY_LIMIT, REFRESH_SECONDS, _format_staleness
from src.analysis.behavioural import compute_behavioural_indicators
from src.analysis.statistics import StatisticsWindow
from src.capture.parser import PacketRecord
from src.reporting.persistence import save_window_result

APP_PATH = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"


def _build_result(window_start=1000.0):
    stats = StatisticsWindow()
    stats.update(PacketRecord("sent", "1.2.3.4", 443, "S", 60, window_start))
    stats.update(PacketRecord("received", "1.2.3.4", 443, "SA", 60, window_start + 1))

    return {
        "stats": stats,
        "indicators": compute_behavioural_indicators(stats),
        "work_weight": 0.5,
        "score": 42,
        "status": "SUSPICIOUS",
        "reasons": ["test reason"],
        "window_start": window_start,
        "window_end": window_start + 30,
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
    assert "50.0%" in metric_values


def test_dashboard_shows_color_coded_status_badge(tmp_path):
    db_path = tmp_path / "dashboard.db"
    save_window_result(db_path, _build_result())

    at = _run_app_with_db(db_path)

    assert not at.exception
    assert any(m.value == ":orange-badge[SUSPICIOUS]" for m in at.markdown)


def test_dashboard_shows_human_readable_window_time(tmp_path):
    db_path = tmp_path / "dashboard.db"
    save_window_result(db_path, _build_result())

    at = _run_app_with_db(db_path)

    assert not at.exception
    expected_time = time.strftime("%H:%M:%S", time.localtime(1000.0))
    table = at.dataframe[0].value
    assert table["Inizio finestra"].iloc[0] == expected_time


def test_format_staleness_scales_across_units():
    assert _format_staleness(5) == "5s fa"
    assert _format_staleness(59) == "59s fa"
    assert _format_staleness(60) == "1m fa"
    assert _format_staleness(3599) == "59m fa"
    assert _format_staleness(3600) == "1h fa"
    assert _format_staleness(86399) == "23h fa"
    assert _format_staleness(86400) == "1g fa"
    assert _format_staleness(-5) == "0s fa"


def test_dashboard_shows_staleness_caption(tmp_path):
    db_path = tmp_path / "dashboard.db"
    save_window_result(db_path, _build_result())

    at = _run_app_with_db(db_path)

    assert not at.exception
    caption_values = [c.value for c in at.caption]
    assert any(c.startswith("Ultimo aggiornamento:") and c.endswith("fa") for c in caption_values)


def test_sidebar_has_refresh_and_history_controls_with_defaults(tmp_path):
    at = _run_app_with_db(tmp_path / "does_not_exist.db")

    assert not at.exception
    assert at.sidebar.number_input[0].value == REFRESH_SECONDS
    assert at.sidebar.number_input[1].value == HISTORY_LIMIT


def test_history_limit_control_limits_displayed_rows(tmp_path):
    db_path = tmp_path / "dashboard.db"
    for window_start in (1000.0, 1030.0, 1060.0):
        save_window_result(db_path, _build_result(window_start))

    at = _run_app_with_db(db_path)
    at.sidebar.number_input[1].set_value(2).run(timeout=15)

    assert not at.exception
    table = at.dataframe[0].value
    assert len(table) == 2
