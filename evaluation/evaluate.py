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

Avvio: python -m evaluation.evaluate [--manifest PATH] [-w WINDOW] [-j JOBS] [--json OUT]
"""

import argparse
import json
import statistics
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
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
    prodotti da `summarize_windows`. Oltre ai tassi per finestra calcola i
    tassi per cattura: quota di catture con almeno una finestra in alert,
    escluse quelle senza finestre (nessun traffico TCP dell'host).
    """
    metrics = {}
    for label, summaries in summaries_by_label.items():
        windows = sum(s["windows"] for s in summaries)
        alerts = sum(s["alert_rate"] * s["windows"] for s in summaries)
        with_traffic = [s for s in summaries if s["windows"] > 0]
        alerted = [s for s in with_traffic if s["alert_rate"] > 0]
        metrics[label] = {
            "captures": len(summaries),
            "captures_with_traffic": len(with_traffic),
            "windows": windows,
            "alert_rate": alerts / windows if windows else 0.0,
            "capture_alert_rate": len(alerted) / len(with_traffic) if with_traffic else 0.0,
        }

    if "botnet" in metrics:
        metrics["detection_rate"] = metrics["botnet"]["alert_rate"]
        metrics["capture_detection_rate"] = metrics["botnet"]["capture_alert_rate"]
    if "normal" in metrics:
        metrics["false_positive_rate"] = metrics["normal"]["alert_rate"]
        metrics["capture_false_positive_rate"] = metrics["normal"]["capture_alert_rate"]
    return metrics


def _replay_and_summarize(dataset, pcap_path, window_size):
    summary = summarize_windows(replay_pcap(pcap_path, dataset["local_ip"], window_size))
    summary["name"] = dataset["name"]
    summary["label"] = dataset["label"]
    # "tuning": catture usate per tarare le soglie (vedi
    # docs/valutazione_dataset.md), i loro numeri non sono una validazione.
    summary["split"] = dataset.get("split", "holdout")
    return summary


def _group_metrics(results, key=None):
    by_label = {}
    for summary in results:
        if key is None or summary["split"] == key:
            by_label.setdefault(summary["label"], []).append(summary)
    return compute_metrics(by_label)


def evaluate(datasets, window_size=WINDOW_SIZE, base_dir=Path("."), jobs=1):
    """Con `jobs` > 1 le catture vengono rilette in processi separati: il
    parsing Scapy è CPU-bound e ogni cattura è indipendente."""
    tasks = []
    for dataset in datasets:
        pcap_path = base_dir / dataset["pcap"]
        if not pcap_path.exists():
            print(f"[skip] {dataset['name']}: {pcap_path} non trovato", file=sys.stderr)
            continue
        tasks.append((dataset, pcap_path))

    if jobs > 1:
        with ProcessPoolExecutor(max_workers=jobs) as pool:
            futures = [pool.submit(_replay_and_summarize, d, p, window_size) for d, p in tasks]
            results = []
            for i, future in enumerate(futures, start=1):
                results.append(future.result())
                print(f"[{i}/{len(tasks)}] {results[-1]['name']}", file=sys.stderr)
    else:
        results = []
        for dataset, pcap_path in tasks:
            print(f"[replay] {dataset['name']} ({pcap_path})", file=sys.stderr)
            results.append(_replay_and_summarize(dataset, pcap_path, window_size))

    splits = sorted({r["split"] for r in results})
    return {
        "window_size": window_size,
        "datasets": results,
        "metrics": _group_metrics(results),
        "metrics_by_split": {split: _group_metrics(results, split) for split in splits},
    }


def _format_metrics(metrics):
    lines = []
    if "detection_rate" in metrics:
        b = metrics["botnet"]
        lines.append(
            f"  Detection: finestre {metrics['detection_rate'] * 100:.1f}% di {b['windows']}, "
            f"catture {metrics['capture_detection_rate'] * 100:.1f}% di {b['captures_with_traffic']}"
        )
    if "false_positive_rate" in metrics:
        n = metrics["normal"]
        lines.append(
            f"  False positive: finestre {metrics['false_positive_rate'] * 100:.1f}% di {n['windows']}, "
            f"catture {metrics['capture_false_positive_rate'] * 100:.1f}% di {n['captures_with_traffic']}"
        )
    return lines


def format_report(report):
    """Una riga per cattura; il dettaglio dei reasons è aggregato per
    etichetta (quello per cattura resta nel JSON di --json)."""
    lines = [f"Finestra: {report['window_size']}s", ""]
    for d in sorted(report["datasets"], key=lambda d: (d["split"], d["label"], d["name"])):
        lines.append(
            f"[{d['split']}/{d['label']}] {d['name']}: finestre {d['windows']}, "
            f"alert {d['alert_rate'] * 100:.1f}%, score medio/max {d['score_mean']:.1f}/{d['score_max']}"
        )

    for label in ("botnet", "normal"):
        reasons = Counter()
        for d in report["datasets"]:
            if d["label"] == label:
                reasons.update(d["reasons"])
        if reasons:
            lines.append("")
            lines.append(f"Reasons nelle finestre {label}:")
            lines.extend(f"  - {reason}: {count}" for reason, count in reasons.most_common())

    for split, metrics in report["metrics_by_split"].items():
        lines.append("")
        lines.append(f"Metriche [{split}]:")
        lines.extend(_format_metrics(metrics))
    lines.append("")
    lines.append("Metriche [tutte le catture]:")
    lines.extend(_format_metrics(report["metrics"]))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validazione del detector su PCAP etichettati")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("-w", "--window", type=int, default=WINDOW_SIZE)
    parser.add_argument("-j", "--jobs", type=int, default=1, help="Processi in parallelo (default: 1)")
    parser.add_argument("--json", default=None, help="Salva il report completo in JSON")
    args = parser.parse_args(argv)

    report = evaluate(load_manifest(args.manifest), window_size=args.window, jobs=args.jobs)
    print(format_report(report))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
