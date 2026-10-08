"""Validazione del detector su dataset PCAP etichettati.

Rilegge offline ciascun PCAP del manifest (vedi evaluation/datasets.json) con
lo stesso Detector usato in live, raccoglie il risultato di ogni finestra e
calcola metriche a livello di finestra:

- sui dataset "botnet": detection rate (finestre SUSPICIOUS o HIGH RISK);
- sui dataset "normal": false positive rate (stessa definizione).

L'etichetta è assegnata per cattura, non per finestra: anche una cattura
botnet contiene finestre in cui il bot è inattivo o genera traffico
legittimo, quindi il detection rate è una stima per difetto. Il conteggio
dei reasons per etichetta serve a capire QUALI indicatori scattano, non
solo quante volte.

Avvio: python -m evaluation.evaluate [--manifest PATH] [-w WINDOW] [--json OUT]
"""

import argparse
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import WINDOW_SIZE
from src.detector import Detector
from src.filtering.whitelist import Whitelist

DEFAULT_MANIFEST = Path(__file__).resolve().parent / "datasets.json"
ALERT_STATUSES = ("SUSPICIOUS", "HIGH RISK")


def load_manifest(path):
    with open(path) as f:
        return json.load(f)["datasets"]


def replay_pcap(pcap_path, local_ip, window_size=WINDOW_SIZE):
    """Restituisce la lista dei risultati per finestra di un PCAP.

    La whitelist è vuota di proposito: la valutazione deve essere
    riproducibile e non dipendere da un whitelist.json locale.
    """
    windows = []
    detector = Detector(
        local_ip=local_ip,
        window_size=window_size,
        on_window_complete=windows.append,
        whitelist=Whitelist(),
        pcap_path=str(pcap_path),
    )
    detector.run()
    return windows


def reason_key(reason):
    """Toglie il valore numerico per poter aggregare lo stesso reason tra
    finestre: i reasons lo riportano tra parentesi ("High Work Weight (80%)")
    oppure dopo una virgola ("Port sweep ..., diversity index 0.90")."""
    return reason.split(" (")[0].split(", ")[0]


def summarize_windows(windows):
    scores = [w["score"] for w in windows]
    statuses = Counter(w["status"] for w in windows)
    reasons = Counter(reason_key(r) for w in windows for r in w["reasons"])
    alerts = sum(statuses[s] for s in ALERT_STATUSES)

    return {
        "windows": len(windows),
        "statuses": dict(statuses),
        "alert_rate": alerts / len(windows) if windows else 0.0,
        "score_mean": statistics.mean(scores) if scores else 0.0,
        "score_median": statistics.median(scores) if scores else 0.0,
        "score_max": max(scores) if scores else 0,
        "reasons": dict(reasons.most_common()),
    }


def compute_metrics(summaries_by_label):
    """Aggrega le finestre di tutti i dataset con la stessa etichetta.

    `summaries_by_label` mappa "botnet"/"normal" a una lista di sommari
    prodotti da `summarize_windows`.
    """
    metrics = {}
    for label, summaries in summaries_by_label.items():
        windows = sum(s["windows"] for s in summaries)
        alerts = sum(s["alert_rate"] * s["windows"] for s in summaries)
        metrics[label] = {
            "windows": windows,
            "alert_rate": alerts / windows if windows else 0.0,
        }

    if "botnet" in metrics:
        metrics["detection_rate"] = metrics["botnet"]["alert_rate"]
    if "normal" in metrics:
        metrics["false_positive_rate"] = metrics["normal"]["alert_rate"]
    return metrics


def evaluate(datasets, window_size=WINDOW_SIZE, base_dir=Path(".")):
    results = []
    summaries_by_label = {}

    for dataset in datasets:
        pcap_path = base_dir / dataset["pcap"]
        if not pcap_path.exists():
            print(f"[skip] {dataset['name']}: {pcap_path} non trovato", file=sys.stderr)
            continue

        print(f"[replay] {dataset['name']} ({pcap_path})", file=sys.stderr)
        summary = summarize_windows(replay_pcap(pcap_path, dataset["local_ip"], window_size))
        summary["name"] = dataset["name"]
        summary["label"] = dataset["label"]
        results.append(summary)
        summaries_by_label.setdefault(dataset["label"], []).append(summary)

    return {
        "window_size": window_size,
        "datasets": results,
        "metrics": compute_metrics(summaries_by_label),
    }


def format_report(report):
    lines = [f"Finestra: {report['window_size']}s", ""]
    for d in report["datasets"]:
        lines.append(f"== {d['name']} [{d['label']}]")
        lines.append(
            f"   finestre: {d['windows']}  alert: {d['alert_rate'] * 100:.1f}%  "
            f"score medio/mediano/max: {d['score_mean']:.1f}/{d['score_median']:.0f}/{d['score_max']}"
        )
        lines.append(f"   status: {d['statuses']}")
        for reason, count in d["reasons"].items():
            lines.append(f"   - {reason}: {count}")
        lines.append("")

    metrics = report["metrics"]
    if "detection_rate" in metrics:
        lines.append(f"Detection rate (finestre botnet): {metrics['detection_rate'] * 100:.1f}%")
    if "false_positive_rate" in metrics:
        lines.append(f"False positive rate (finestre normali): {metrics['false_positive_rate'] * 100:.1f}%")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validazione del detector su PCAP etichettati")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("-w", "--window", type=int, default=WINDOW_SIZE)
    parser.add_argument("--json", default=None, help="Salva il report completo in JSON")
    args = parser.parse_args(argv)

    report = evaluate(load_manifest(args.manifest), window_size=args.window)
    print(format_report(report))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
