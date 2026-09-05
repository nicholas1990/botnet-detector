from unittest.mock import patch

from src.config import WINDOW_SIZE
from src.main import build_arg_parser, build_on_window_complete, main
from src.reporting.console import print_window_report


def test_arg_parser_defaults():
    args = build_arg_parser().parse_args([])

    assert args.interface is None
    assert args.window == WINDOW_SIZE
    assert args.dashboard_db is None


def test_arg_parser_custom_values():
    args = build_arg_parser().parse_args(["--interface", "eth0", "--window", "60"])

    assert args.interface == "eth0"
    assert args.window == 60


def test_main_wires_detector_with_resolved_ip_and_runs_it():
    with patch("src.main.resolve_local_ip", return_value="192.168.1.10") as mock_resolve, \
         patch("src.main.Detector") as mock_detector_cls:
        main(["--interface", "eth0", "--window", "10"])

    mock_resolve.assert_called_once_with("eth0")
    mock_detector_cls.assert_called_once_with(
        local_ip="192.168.1.10",
        interface="eth0",
        window_size=10,
        on_window_complete=print_window_report,
    )
    mock_detector_cls.return_value.run.assert_called_once()


def test_arg_parser_accepts_dashboard_db():
    args = build_arg_parser().parse_args(["--dashboard-db", "dashboard.db"])

    assert args.dashboard_db == "dashboard.db"


def test_build_on_window_complete_returns_console_report_when_no_dashboard_db():
    assert build_on_window_complete(None) is print_window_report


def test_build_on_window_complete_also_persists_when_dashboard_db_given():
    result = {"score": 0}

    with patch("src.main.print_window_report") as mock_print, \
         patch("src.main.save_window_result") as mock_save:
        on_window_complete = build_on_window_complete("dashboard.db")
        on_window_complete(result)

    mock_print.assert_called_once_with(result)
    mock_save.assert_called_once_with("dashboard.db", result)


def test_main_wires_dashboard_db_into_detector():
    with patch("src.main.resolve_local_ip", return_value="192.168.1.10"), \
         patch("src.main.Detector") as mock_detector_cls:
        main(["--dashboard-db", "dashboard.db"])

    on_window_complete = mock_detector_cls.call_args.kwargs["on_window_complete"]
    assert on_window_complete is not print_window_report
