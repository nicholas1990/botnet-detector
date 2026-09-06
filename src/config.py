"""Configurazione globale del detector."""

WINDOW_SIZE = 30  # secondi

RISK_THRESHOLD_SUSPICIOUS = 30
RISK_THRESHOLD_HIGH = 60

# Whitelist servizi legittimi TCP (specifiche_botanalyzer_netflow.md sez. 14).
# File assente -> whitelist no-op, nessun impatto sul comportamento esistente.
WHITELIST_PATH = "whitelist.json"

# Percorso suggerito per il database SQLite condiviso con la dashboard
# (sez. 11): usato come default nella UI di dashboard/app.py. Il detector
# scrive qui solo se avviato con --dashboard-db (opt-in, vedi src/main.py).
DASHBOARD_DB_PATH = "dashboard.db"

# Numero massimo di righe (finestre) mantenute nel database della dashboard.
# Il detector può girare per giorni/settimane scrivendo una riga ogni
# WINDOW_SIZE secondi; senza un limite il file crescerebbe indefinitamente.
# La dashboard mostra al più HISTORY_LIMIT righe alla volta, quindi un
# margine ben più ampio preserva comunque uno storico utile su disco.
DASHBOARD_RETENTION_ROWS = 5000

# Soglie minime di campione sotto le quali un indice di diversità non è
# affidabile (specifiche sez. 3) e va ignorato. Centralizzate qui anche se
# applicate in punti diversi (src/analysis/behavioural.py per il filtro
# per-destinazione, src/scoring/risk_score.py per il controllo aggregato)
# per tenere le soglie di tuning in un solo posto.
MIN_PACKETS_FOR_DIVERSITY = 5
MIN_PACKETS_PER_DESTINATION_FOR_DDP = 3
MIN_FLOWS_PER_DESTINATION_FOR_TBF = 3
