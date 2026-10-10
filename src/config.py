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

# TBF: SYN verso la stessa destinazione distanti meno di così (dal SYN
# precedente) vengono fusi in un unico evento prima di calcolare gli
# intervalli. Senza questo raggruppamento le connessioni parallele aperte
# dal browser nello stesso istante producono delta tutti nel bin 0ms e
# vengono scambiate per beaconing perfettamente regolare (vedi
# docs/valutazione_dataset.md). Un C&C che si ricollega più di una volta al
# secondo non è un caso realistico di beaconing.
TBF_MERGE_GAP_SECONDS = 1.0

# Memoria tra finestre (beaconing a lungo periodo, src/analysis/history.py):
# un C&C con connessioni riuscite si ricollega ogni minuti o ore, quindi in
# una finestra di 30s non lascia traccia. Si segnala una destinazione
# (IP, porta) quando gli ultimi LONG_BEACONING_MIN_EVENTS eventi di
# connessione hanno periodo medio tra MIN e MAX_PERIOD_SECONDS, intervalli
# regolari (coefficiente di variazione <= MAX_INTERVAL_CV) e byte inviati
# per evento simili (<= MAX_BYTES_CV). Valori tarati solo sullo split
# "tuning" delle catture Stratosphere (vedi docs/valutazione_dataset.md):
# 8 eventi e byte simili escludono quasi tutte le destinazioni periodiche
# del browsing normale, che con 4-6 eventi comparivano in quasi ogni cattura.
LONG_BEACONING_MIN_EVENTS = 8
LONG_BEACONING_MIN_PERIOD_SECONDS = 15
LONG_BEACONING_MAX_PERIOD_SECONDS = 3600
LONG_BEACONING_MAX_INTERVAL_CV = 0.2
LONG_BEACONING_MAX_BYTES_CV = 0.2
# Limite alle destinazioni ricordate: uno scan ne genera migliaia l'ora e
# senza limite la memoria crescerebbe con il fan-out. Si scartano le meno
# recenti, che non possono comunque essere beaconing in corso.
LONG_BEACONING_MAX_TRACKED_DESTINATIONS = 50000
