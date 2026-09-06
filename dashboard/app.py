"""Dashboard web locale (opzionale) per la visualizzazione del detector.

Processo separato, non privilegiato: legge periodicamente i risultati che il
Detector scrive su SQLite (opzione (b), vedi docs/roadmap.md e
src/reporting/persistence.py) invece di condividere memoria/thread con il
processo di cattura, che gira privilegiato.

Avvio: streamlit run dashboard/app.py
Richiede il detector avviato con: sudo python -m src.main --dashboard-db <path>
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import DASHBOARD_DB_PATH
from src.reporting.persistence import fetch_recent_results

REFRESH_SECONDS = 5
HISTORY_LIMIT = 100


@st.fragment(run_every=REFRESH_SECONDS)
def render(db_path):
    results = fetch_recent_results(db_path, limit=HISTORY_LIMIT)

    if not results:
        st.info(
            "Nessun dato ancora disponibile. Avvia il detector con "
            "--dashboard-db per popolare questa dashboard."
        )
        return

    latest = results[0]
    history = list(reversed(results))

    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Score", f"{latest['score']}/100")
    col2.metric("Status", latest["status"])
    col3.metric("TCP Work Weight", f"{latest['work_weight'] * 100:.1f}%")

    if latest["reasons"]:
        st.warning("\n".join(f"- {reason}" for reason in latest["reasons"]))

    chart_data = pd.DataFrame(
        {
            "window_start": [entry["window_start"] for entry in history],
            "Risk Score": [entry["score"] for entry in history],
        }
    ).set_index("window_start")
    st.line_chart(chart_data)

    st.subheader("Ultime finestre")
    table_data = pd.DataFrame(
        [
            {
                "Inizio finestra": entry["window_start"],
                "Score": entry["score"],
                "Status": entry["status"],
                "TCP packets": entry["tcp_packets"],
                "SYN": entry["syn_sent"],
                "SYN-ACK": entry["syn_ack_received"],
                "IP dest. uniche": entry["unique_destination_ips"],
                "Porte dest. uniche": entry["unique_destination_ports"],
            }
            for entry in results
        ]
    )
    st.dataframe(table_data, width="stretch")


def main():
    st.set_page_config(page_title="Host Network Anomaly Detector", layout="wide")
    st.title("Host Network Anomaly Detector")

    db_path = st.sidebar.text_input("Database dashboard", value=DASHBOARD_DB_PATH)
    st.sidebar.caption(f"Aggiornamento automatico ogni {REFRESH_SECONDS}s")

    render(db_path)


if __name__ == "__main__":
    main()
