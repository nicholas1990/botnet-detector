"""Persistenza dei risultati per finestra su SQLite (spec sez. 11).

Meccanismo di condivisione dati scelto per la dashboard (vedi docs/roadmap.md):
il `Detector`, che gira privilegiato per la cattura, scrive qui un risultato
per ogni finestra chiusa; la dashboard Streamlit, non privilegiata, legge
periodicamente da qui con `fetch_recent_results`. Nessuna comunicazione
diretta tra i due processi.
"""

import json
import sqlite3

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS window_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    score INTEGER NOT NULL,
    status TEXT NOT NULL,
    work_weight REAL NOT NULL,
    tcp_packets INTEGER NOT NULL,
    syn_sent INTEGER NOT NULL,
    syn_ack_received INTEGER NOT NULL,
    fin_sent INTEGER NOT NULL,
    rst_received INTEGER NOT NULL,
    unique_destination_ips INTEGER NOT NULL,
    unique_destination_ports INTEGER NOT NULL,
    reasons TEXT NOT NULL,
    indicators TEXT NOT NULL
)
"""

INSERT_SQL = """
INSERT INTO window_results (
    window_start, window_end, score, status, work_weight,
    tcp_packets, syn_sent, syn_ack_received, fin_sent, rst_received,
    unique_destination_ips, unique_destination_ports, reasons, indicators
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

SELECT_RECENT_SQL = """
SELECT window_start, window_end, score, status, work_weight,
       tcp_packets, syn_sent, syn_ack_received, fin_sent, rst_received,
       unique_destination_ips, unique_destination_ports, reasons, indicators
FROM window_results
ORDER BY window_start DESC
LIMIT ?
"""


def _connect(db_path):
    # WAL: il Detector (scrittore) e la dashboard (lettore) sono processi
    # separati che accedono allo stesso file in concorrenza.
    connection = sqlite3.connect(db_path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(CREATE_TABLE_SQL)
    return connection


def save_window_result(db_path, result):
    """Scrive un risultato di finestra (vedi Detector._close_window) su SQLite."""
    stats = result["stats"]
    total_tcp_packets = stats.packets_sent + stats.packets_received

    with _connect(db_path) as connection:
        connection.execute(
            INSERT_SQL,
            (
                result["window_start"],
                result["window_end"],
                result["score"],
                result["status"],
                result["work_weight"],
                total_tcp_packets,
                stats.syn_sent,
                stats.syn_ack_received,
                stats.fin_sent,
                stats.rst_received,
                len(stats.unique_destination_ips),
                len(stats.unique_destination_ports),
                json.dumps(result["reasons"]),
                json.dumps(result["indicators"]),
            ),
        )


def fetch_recent_results(db_path, limit=50):
    """Legge le ultime `limit` finestre, più recente prima (per la dashboard)."""
    columns = [
        "window_start", "window_end", "score", "status", "work_weight",
        "tcp_packets", "syn_sent", "syn_ack_received", "fin_sent", "rst_received",
        "unique_destination_ips", "unique_destination_ports", "reasons", "indicators",
    ]

    with _connect(db_path) as connection:
        rows = connection.execute(SELECT_RECENT_SQL, (limit,)).fetchall()

    results = []
    for row in rows:
        entry = dict(zip(columns, row))
        entry["reasons"] = json.loads(entry["reasons"])
        entry["indicators"] = json.loads(entry["indicators"])
        results.append(entry)
    return results
