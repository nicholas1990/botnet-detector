"""Entry point del Network Anomaly Detector."""

import argparse

from scapy.arch import get_if_addr
from scapy.config import conf

from src.config import WINDOW_SIZE
from src.detector import Detector
from src.reporting.console import print_window_report


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Host Network Anomaly / Botnet Detector")
    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help="Interfaccia di rete da monitorare (default: interfaccia di default di Scapy)",
    )
    parser.add_argument(
        "-w",
        "--window",
        type=int,
        default=WINDOW_SIZE,
        help=f"Durata della finestra temporale in secondi (default: {WINDOW_SIZE})",
    )
    return parser


def resolve_local_ip(interface):
    return get_if_addr(interface or conf.iface)


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    local_ip = resolve_local_ip(args.interface)

    detector = Detector(
        local_ip=local_ip,
        interface=args.interface,
        window_size=args.window,
        on_window_complete=print_window_report,
    )
    detector.run()


if __name__ == "__main__":
    main()
