"""Divide un manifest in split "tuning" e "holdout" per gruppi disgiunti.

Le soglie vanno tarate solo sulle catture "tuning" e verificate sulle
"holdout". Dividere cattura per cattura non basta: due catture della stessa
famiglia di malware (o dello stesso host normale) si somigliano, e una
soglia tarata sull'una funzionerebbe sull'altra per lo stesso motivo per
cui funzionava sui dati di taratura. Per questo l'unità della divisione è
il gruppo:

- malware di famiglia nota: un gruppo per famiglia (alias in FAMILY_ALIASES);
- malware identificato solo dall'MD5 del binario: un gruppo per MD5;
- malware senza nome o con un nome generico ("Artemis", "Trojan.Agent",
  un MD5): un gruppo per esperimento, cioè il dataset senza il suffisso
  della sotto-cattura (CTU-Malware-Capture-Botnet-140-1 e -2 insieme);
- catture normali: un gruppo per cattura, salvo quelle dello stesso host e
  della stessa sessione (SAME_SESSION).

I gruppi che contengono catture già usate per la taratura restano in
"tuning". Gli altri sono ordinati per hash del nome (ordine deterministico
ma non scelto guardando i risultati) e assegnati a "tuning" finché questo
non raggiunge TUNING_SHARE delle catture della stessa etichetta.

I nomi delle famiglie vengono dal campo "Probable name" dei README
Stratosphere, salvati in evaluation/stratosphere_names.json
(dataset -> nome, null se assente).

Avvio: python -m evaluation.split_manifest MANIFEST NAMES [--share 0.4]
(riscrive MANIFEST aggiungendo "group" e aggiornando "split").
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

TUNING_SHARE = 0.4
SALT = "botnet-detector-split-v1"
TUNING_DATASETS = {"CTU-Malware-Capture-Botnet-42", "CTU-Normal-20"}
SAME_SESSION = {"CTU-Normal-22": "CTU-Normal-21"}

# Chiave cercata nel nome (minuscolo) -> famiglia canonica. L'ordine conta:
# "Cerber Ransomware installed by trojanized Ammyy" è Cerber, non Ammyy.
FAMILY_ALIASES = [
    ("trickbot", "trickbot"), ("trickster", "trickbot"),
    ("emotet", "emotet"), ("geodo", "emotet"),
    ("zbot", "zeus"), ("zeus", "zeus"),
    ("dridex", "dridex"), ("cridex", "dridex"),
    ("wannacry", "wannacry"), ("notpetya", "notpetya"),
    ("cerber", "cerber"), ("ammyy", "ammyy"),
    ("locky", "locky"), ("tinba", "tinba"), ("bunitu", "bunitu"),
    ("kelihos", "kelihos"), ("upatre", "upatre"), ("sality", "sality"),
    ("necurse", "necurse"), ("virut", "virut"), ("rbot", "rbot"),
    ("neris", "neris"), ("donbot", "donbot"), ("conficker", "conficker"),
    ("vawtrak", "vawtrak"), ("miuref", "miuref"), ("razy", "razy"),
    ("bladabindi", "bladabindi"), ("kovter", "kovter"), ("rasftuby", "rasftuby"),
    ("strictor", "strictor"), ("opencandy", "opencandy"), ("taobao", "taobao"),
    ("toolbar", "toolbar"), ("downloadguide", "downloadguide"),
    ("ursnif", "ursnif"), ("gh0st", "gh0st"), ("sogou", "sogou"),
    ("murlo", "murlo"), ("nsis.ay", "nsis.ay"), ("allaple", "allaple"),
    ("pushdo", "pushdo"), ("simda", "simda"), ("dyreza", "dyreza"),
    ("hancitor", "hancitor"), ("shifu", "shifu"), ("cryptowall", "cryptowall"),
    ("xmrig", "xmrig"), ("flubot", "flubot"), ("luminositylink", "luminositylink"),
    ("sathurbot", "sathurbot"), ("htbot", "htbot"), ("andromeda", "andromeda"),
]


def canonical_family(name):
    """Famiglia canonica dal "Probable name" del README, None se il nome è
    assente o generico (non identifica una famiglia)."""
    if not name:
        return None
    lowered = name.lower()
    md5 = re.match(r"md5:\s*([0-9a-f]{32})", lowered)
    if md5:
        return "md5:" + md5.group(1)
    for key, family in FAMILY_ALIASES:
        if key in lowered:
            return family
    return None


def experiment_id(dataset):
    return re.sub(r"(Botnet-\d+)-\d+$", r"\1", dataset)


def group_of(dataset, label, names):
    if label == "normal":
        return "normal:" + SAME_SESSION.get(dataset, dataset)
    family = canonical_family(names.get(dataset))
    return f"family:{family}" if family else "experiment:" + experiment_id(dataset)


def _dataset_of(entry):
    return Path(entry["pcap"]).parent.name


def _hash(group):
    return hashlib.sha256(f"{SALT}:{group}".encode()).hexdigest()


def assign_splits(datasets, names, tuning_share=TUNING_SHARE):
    for entry in datasets:
        entry["group"] = group_of(_dataset_of(entry), entry["label"], names)

    for label in {entry["label"] for entry in datasets}:
        entries = [e for e in datasets if e["label"] == label]
        sizes = {}
        for entry in entries:
            sizes[entry["group"]] = sizes.get(entry["group"], 0) + 1
        forced = {e["group"] for e in entries if _dataset_of(e) in TUNING_DATASETS}

        tuning = set(forced)
        target = tuning_share * len(entries)
        count = sum(sizes[g] for g in tuning)
        for group in sorted(set(sizes) - forced, key=_hash):
            if count >= target:
                break
            tuning.add(group)
            count += sizes[group]

        for entry in entries:
            entry["split"] = "tuning" if entry["group"] in tuning else "holdout"
    return datasets


def main(argv=None):
    parser = argparse.ArgumentParser(description="Split tuning/holdout per gruppi disgiunti")
    parser.add_argument("manifest")
    parser.add_argument("names")
    parser.add_argument("--share", type=float, default=TUNING_SHARE)
    args = parser.parse_args(argv)

    with open(args.manifest) as f:
        manifest = json.load(f)
    with open(args.names) as f:
        names = json.load(f)
    assign_splits(manifest["datasets"], names, args.share)
    with open(args.manifest, "w") as f:
        json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    main()
