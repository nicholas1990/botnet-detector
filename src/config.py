"""Configurazione globale del detector."""

WINDOW_SIZE = 30  # secondi

RISK_THRESHOLD_SUSPICIOUS = 30
RISK_THRESHOLD_HIGH = 60

# Whitelist servizi legittimi TCP (specifiche_botanalyzer_netflow.md sez. 14).
# File assente -> whitelist no-op, nessun impatto sul comportamento esistente.
WHITELIST_PATH = "whitelist.json"
