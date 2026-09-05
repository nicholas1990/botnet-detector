"""Entry point del Network Anomaly Detector."""

import argparse

from scapy.arch import get_if_addr
from scapy.config import conf

from src.config import WINDOW_SIZE
from src.detector import Detector
from src.reporting.console import print_window_report
from src.reporting.persistence import save_window_result


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
    parser.add_argument(
        "--dashboard-db",
        default=None,
        help="Percorso del database SQLite per la dashboard (default: disabilitato)",
    )
    return parser


def resolve_local_ip(interface):
    return get_if_addr(interface or conf.iface)


def build_on_window_complete(dashboard_db):
    """Il report console resta sempre attivo; la scrittura su SQLite per la
    dashboard (spec sez. 11) è opt-in via --dashboard-db, per non imporre
    quella dipendenza a chi usa solo il detector da riga di comando."""
    if dashboard_db is None:
        return print_window_report

    def on_window_complete(result):
        print_window_report(result)
        save_window_result(dashboard_db, result)

    return on_window_complete


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    local_ip = resolve_local_ip(args.interface)

    detector = Detector(
        local_ip=local_ip,
        interface=args.interface,
        window_size=args.window,
        on_window_complete=build_on_window_complete(args.dashboard_db),
    )
    detector.run()


if __name__ == "__main__":
    main()
