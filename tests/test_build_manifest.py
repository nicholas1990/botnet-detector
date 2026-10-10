from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from evaluation.build_manifest import build_manifest, ip_shares, is_excluded, monitored_hosts


def _write(path, pairs):
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), [IP(src=s, dst=d) / TCP() for s, d in pairs])


def test_ip_shares_counts_source_and_destination(tmp_path):
    pcap = tmp_path / "a.pcap"
    _write(pcap, [("10.0.0.5", "1.1.1.1"), ("2.2.2.2", "10.0.0.5")])

    shares = ip_shares(pcap)

    assert shares["10.0.0.5"] == 1.0
    assert shares["1.1.1.1"] == 0.5


def test_monitored_hosts_picks_dominant_ip():
    assert monitored_hosts({"10.0.0.5": 0.95, "1.1.1.1": 0.3}, "capture.pcap") == ["10.0.0.5"]


def test_monitored_hosts_splits_ctu13_multi_bot_captures():
    shares = {"147.32.84.165": 0.5, "147.32.84.191": 0.4, "147.32.84.1": 0.01, "8.8.8.8": 0.3}

    assert monitored_hosts(shares, "botnet-capture-20110816-sogou.pcap") == [
        "147.32.84.165",
        "147.32.84.191",
    ]


def test_monitored_hosts_rejects_ambiguous_captures():
    assert monitored_hosts({"10.0.0.5": 0.5, "10.0.0.6": 0.5}, "capture.pcap") == []
    assert monitored_hosts({}, "capture.pcap") == []


def test_build_manifest_labels_and_splits_by_dataset(tmp_path):
    _write(tmp_path / "CTU-Normal-20" / "n.pcap", [("10.0.2.15", "1.1.1.1")])
    _write(tmp_path / "CTU-Malware-Capture-Botnet-99" / "m.pcap", [("10.0.2.16", "1.1.1.1")])

    datasets = build_manifest(tmp_path)["datasets"]
    by_name = {d["name"]: d for d in datasets}

    normal = by_name["CTU-Normal-20/n.pcap"]
    assert (normal["label"], normal["split"], normal["local_ip"]) == ("normal", "tuning", "10.0.2.15")
    malware = by_name["CTU-Malware-Capture-Botnet-99/m.pcap"]
    assert (malware["label"], malware["split"]) == ("botnet", "holdout")
    assert malware["source"].endswith("/CTU-Malware-Capture-Botnet-99/m.pcap")


def test_is_excluded_skips_mixed_datasets_slices_and_normal_captures_in_malware_dirs():
    assert is_excluded("CTU-Mixed-Capture-1", "capture.pcap")
    assert is_excluded("CTU-Malware-Capture-Botnet-353-1", "353-1.1000p.pcap")
    assert is_excluded("CTU-Malware-Capture-Botnet-353-1", "353-1.0-5000.pcap")
    assert is_excluded("CTU-Malware-Capture-Botnet-50", "normal-capture-20110817.pcap")
    assert not is_excluded("CTU-Malware-Capture-Botnet-353-1", "2018-05-07_capture.pcap")
    assert not is_excluded("CTU-Normal-21", "2017-05-02_kali-normal.pcap")


def test_build_manifest_ignores_excluded_captures(tmp_path):
    _write(tmp_path / "CTU-Mixed-Capture-1" / "m.pcap", [("10.0.2.15", "1.1.1.1")])

    assert build_manifest(tmp_path)["datasets"] == []
