"""Genera un manifest di valutazione dalle catture Stratosphere scaricate.

Si aspetta la struttura `ROOT/<dataset>/<file>.pcap` (es. scaricata da
https://mcfp.felk.cvut.cz/publicDatasets/<dataset>/<file>.pcap). Per ogni
cattura:

- etichetta: "normal" se il nome del dataset contiene "Normal", altrimenti
  "botnet" (le catture di malware Stratosphere sono registrate sulla VM
  infetta, quindi l'intera cattura è considerata traffico del bot);
- host monitorato: l'IP presente in almeno DOMINANT_SHARE dei pacchetti IP
  iniziali. Le catture CTU-13 "botnet-capture-*" possono contenere più bot
  della rete universitaria (147.32.84.0/24): in quel caso si crea una voce
  per ciascun host con almeno MULTI_HOST_MIN_SHARE dei pacchetti.
  Le catture senza un host chiaramente dominante vengono scartate ed
  elencate su stderr, invece di indovinare.

Le catture usate per tarare le soglie (vedi docs/valutazione_dataset.md)
sono marcate split "tuning", tutte le altre "holdout".

Avvio: python -m evaluation.build_manifest ROOT OUT.json [-j JOBS]
"""

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from scapy.layers.inet import IP
from scapy.utils import PcapReader

SAMPLE_PACKETS = 50000
DOMINANT_SHARE = 0.8
MULTI_HOST_MIN_SHARE = 0.05
CTU13_BOT_PREFIX = "147.32.84."
SOURCE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/{dataset}/{file}"
TUNING_DATASETS = {"CTU-Malware-Capture-Botnet-42", "CTU-Normal-20"}


def ip_shares(pcap_path, sample_packets=SAMPLE_PACKETS):
    """Quota di pacchetti IP in cui compare ciascun indirizzo (sorgente o
    destinazione) nei primi `sample_packets` pacchetti."""
    counts = Counter()
    ip_packets = 0
    try:
        with PcapReader(str(pcap_path)) as reader:
            for i, packet in enumerate(reader):
                if i >= sample_packets:
                    break
                if packet.haslayer(IP):
                    ip_packets += 1
                    counts[packet[IP].src] += 1
                    counts[packet[IP].dst] += 1
    except Exception as error:  # PCAP troncati o in formato non supportato
        print(f"[errore] {pcap_path}: {error}", file=sys.stderr)
    if ip_packets == 0:
        return {}
    return {ip: count / ip_packets for ip, count in counts.items()}


def monitored_hosts(shares, file_name):
    if not shares:
        return []
    top_ip, top_share = max(shares.items(), key=lambda item: item[1])
    if top_share >= DOMINANT_SHARE:
        return [top_ip]
    if file_name.startswith("botnet-capture-"):
        return sorted(
            ip for ip, share in shares.items()
            if ip.startswith(CTU13_BOT_PREFIX) and share >= MULTI_HOST_MIN_SHARE
        )
    return []


def _entries_for(pcap_path, root):
    dataset = pcap_path.parent.name
    hosts = monitored_hosts(ip_shares(pcap_path), pcap_path.name)
    label = "normal" if "Normal" in dataset else "botnet"
    split = "tuning" if dataset in TUNING_DATASETS else "holdout"
    entries = [
        {
            "name": f"{dataset}/{pcap_path.name}" + (f" [{host}]" if len(hosts) > 1 else ""),
            "label": label,
            "split": split,
            "pcap": str(pcap_path),
            "local_ip": host,
            "source": SOURCE_URL.format(dataset=dataset, file=pcap_path.name),
        }
        for host in hosts
    ]
    return pcap_path, entries


def build_manifest(root, jobs=1):
    pcaps = sorted(Path(root).glob("*/*.pcap"))
    datasets = []
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        for pcap_path, entries in pool.map(_entries_for, pcaps, [root] * len(pcaps)):
            if not entries:
                print(f"[scartata] {pcap_path}: nessun host dominante", file=sys.stderr)
            datasets.extend(entries)
    return {"datasets": datasets}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Manifest di valutazione da catture Stratosphere")
    parser.add_argument("root")
    parser.add_argument("out")
    parser.add_argument("-j", "--jobs", type=int, default=1)
    args = parser.parse_args(argv)

    manifest = build_manifest(args.root, jobs=args.jobs)
    with open(args.out, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"{len(manifest['datasets'])} voci scritte in {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
