from unittest.mock import patch

from src.config import WINDOW_SIZE
from src.main import build_arg_parser, main
from src.reporting.console import print_window_report


def test_arg_parser_defaults():
    args = build_arg_parser().parse_args([])

    assert args.interface is None
    assert args.window == WINDOW_SIZE


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
