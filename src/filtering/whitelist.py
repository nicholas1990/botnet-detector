"""Whitelist di servizi legittimi TCP con TTL (specifiche_botanalyzer_netflow.md sez. 14).

Le entry vanno aggiunte manualmente (niente auto-apprendimento) e devono
riportare `added_at` esplicito: allo scadere del `ttl_days` l'entry smette
di valere finché non viene rinnovata a mano, per evitare il
"blind-whitelisting permanente" citato nello spec (un host legittimo
compromesso non deve restare invisibile per sempre).
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TTL_DAYS = 30
SECONDS_PER_DAY = 86400


@dataclass
class WhitelistEntry:
    ip: str | None
    port: int | None
    service: str
    added_at: float
    ttl_days: float = DEFAULT_TTL_DAYS

    def is_expired(self, now):
        return now - self.added_at > self.ttl_days * SECONDS_PER_DAY

    def matches(self, ip, port):
        if self.ip is not None and self.ip != ip:
            return False
        if self.port is not None and self.port != port:
            return False
        return True


class Whitelist:
    def __init__(self, entries=None):
        self.entries = entries or []

    def is_whitelisted(self, ip, port, now=None):
        now = time.time() if now is None else now
        return any(
            entry.matches(ip, port) and not entry.is_expired(now)
            for entry in self.entries
        )


def load_whitelist(path):
    """Carica la whitelist da un file JSON. File assente/vuoto -> whitelist no-op."""
    file_path = Path(path)
    if not file_path.exists():
        return Whitelist()

    with file_path.open() as f:
        data = json.load(f)

    entries = [
        WhitelistEntry(
            ip=entry.get("ip"),
            port=entry.get("port"),
            service=entry["service"],
            added_at=entry["added_at"],
            ttl_days=entry.get("ttl_days", DEFAULT_TTL_DAYS),
        )
        for entry in data.get("entries", [])
    ]
    return Whitelist(entries)
