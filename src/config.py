"""Configurazione globale del detector."""

WINDOW_SIZE = 30  # secondi

RISK_THRESHOLD_SUSPICIOUS = 30
RISK_THRESHOLD_HIGH = 60

# Whitelist servizi legittimi TCP (specifiche_botanalyzer_netflow.md sez. 14).
# File assente -> whitelist no-op, nessun impatto sul comportamento esistente.
WHITELIST_PATH = "whitelist.json"

# Soglie minime di campione sotto le quali un indice di diversità non è
# affidabile (specifiche sez. 3) e va ignorato. Centralizzate qui anche se
# applicate in punti diversi (src/analysis/behavioural.py per il filtro
# per-destinazione, src/scoring/risk_score.py per il controllo aggregato)
# per tenere le soglie di tuning in un solo posto.
MIN_PACKETS_FOR_DIVERSITY = 5
MIN_PACKETS_PER_DESTINATION_FOR_DDP = 3
MIN_FLOWS_PER_DESTINATION_FOR_TBF = 3
