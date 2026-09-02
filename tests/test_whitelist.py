import json

from src.filtering.whitelist import Whitelist, WhitelistEntry, load_whitelist

NOW = 1_700_000_000.0
DAY = 86400


def test_matches_by_ip_only():
    entry = WhitelistEntry(ip="10.0.0.1", port=None, service="VPN", added_at=NOW)

    assert entry.matches("10.0.0.1", 443)
    assert entry.matches("10.0.0.1", 22)
    assert not entry.matches("10.0.0.2", 443)


def test_matches_by_port_only():
    entry = WhitelistEntry(ip=None, port=88, service="Kerberos", added_at=NOW)

    assert entry.matches("1.2.3.4", 88)
    assert entry.matches("5.6.7.8", 88)
    assert not entry.matches("1.2.3.4", 443)


def test_matches_by_ip_and_port():
    entry = WhitelistEntry(ip="10.0.0.1", port=53, service="DNS-over-TCP", added_at=NOW)

    assert entry.matches("10.0.0.1", 53)
    assert not entry.matches("10.0.0.1", 80)
    assert not entry.matches("10.0.0.2", 53)


def test_entry_expires_after_ttl():
    entry = WhitelistEntry(ip="10.0.0.1", port=None, service="VPN", added_at=NOW, ttl_days=30)

    assert not entry.is_expired(NOW + 29 * DAY)
    assert entry.is_expired(NOW + 31 * DAY)


def test_whitelist_is_whitelisted_ignores_expired_entries():
    entry = WhitelistEntry(ip="10.0.0.1", port=None, service="VPN", added_at=NOW, ttl_days=30)
    whitelist = Whitelist([entry])

    assert whitelist.is_whitelisted("10.0.0.1", 443, now=NOW + 1 * DAY)
    assert not whitelist.is_whitelisted("10.0.0.1", 443, now=NOW + 31 * DAY)


def test_empty_whitelist_never_matches():
    whitelist = Whitelist()

    assert not whitelist.is_whitelisted("10.0.0.1", 443, now=NOW)


def test_load_whitelist_returns_empty_when_file_missing(tmp_path):
    whitelist = load_whitelist(tmp_path / "does_not_exist.json")

    assert not whitelist.is_whitelisted("10.0.0.1", 443, now=NOW)


def test_load_whitelist_parses_entries_from_json(tmp_path):
    path = tmp_path / "whitelist.json"
    path.write_text(
        json.dumps(
            {
                "entries": [
                    {"ip": "10.0.0.1", "port": 53, "service": "DNS-over-TCP", "added_at": NOW},
                    {"port": 88, "service": "Kerberos", "added_at": NOW, "ttl_days": 7},
                ]
            }
        )
    )

    whitelist = load_whitelist(path)

    assert whitelist.is_whitelisted("10.0.0.1", 53, now=NOW)
    assert whitelist.is_whitelisted("1.2.3.4", 88, now=NOW + 1 * DAY)
    assert not whitelist.is_whitelisted("1.2.3.4", 88, now=NOW + 8 * DAY)
