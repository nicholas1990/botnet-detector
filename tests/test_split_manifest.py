from evaluation.split_manifest import assign_splits, canonical_family, group_of


def _entry(dataset, label="botnet"):
    return {"pcap": f"data/samples/stratosphere/{dataset}/x.pcap", "label": label}


def test_canonical_family_merges_aliases_and_ignores_generic_names():
    assert canonical_family("Trojan.Trickster") == "trickbot"
    assert canonical_family("Geodo") == "emotet"
    assert canonical_family("Cerber Ransomware installed by trojanized Ammyy Remote Admin") == "cerber"
    assert canonical_family("MD5: d4ad1c4d827f9ef4b108f35eef144a34") == "md5:d4ad1c4d827f9ef4b108f35eef144a34"
    assert canonical_family("Artemis") is None
    assert canonical_family(None) is None


def test_group_of_falls_back_to_experiment_and_merges_same_session_normals():
    names = {"CTU-Malware-Capture-Botnet-140-1": "Artemis"}

    assert group_of("CTU-Malware-Capture-Botnet-140-1", "botnet", names) == "experiment:CTU-Malware-Capture-Botnet-140"
    assert group_of("CTU-Malware-Capture-Botnet-17", "botnet", {}) == "experiment:CTU-Malware-Capture-Botnet-17"
    assert group_of("CTU-Normal-22", "normal", {}) == group_of("CTU-Normal-21", "normal", {})


def test_assign_splits_never_puts_a_group_in_both_splits():
    names = {f"CTU-Malware-Capture-Botnet-{i}": "TrickBot" if i < 5 else None for i in range(20)}
    datasets = [_entry(f"CTU-Malware-Capture-Botnet-{i}") for i in range(20)]

    assign_splits(datasets, names, tuning_share=0.4)

    splits_by_group = {}
    for entry in datasets:
        splits_by_group.setdefault(entry["group"], set()).add(entry["split"])
    assert all(len(splits) == 1 for splits in splits_by_group.values())
    assert {e["split"] for e in datasets} == {"tuning", "holdout"}


def test_assign_splits_keeps_previous_tuning_captures_in_tuning():
    names = {"CTU-Malware-Capture-Botnet-42": "Neris", "CTU-Malware-Capture-Botnet-43": "Neris"}
    datasets = [_entry("CTU-Malware-Capture-Botnet-42"), _entry("CTU-Malware-Capture-Botnet-43")]

    assign_splits(datasets, names, tuning_share=0.0)

    assert [e["split"] for e in datasets] == ["tuning", "tuning"]


def test_assign_splits_is_deterministic():
    names = {}
    first = assign_splits([_entry(f"CTU-Normal-{i}", "normal") for i in range(10)], names)
    second = assign_splits([_entry(f"CTU-Normal-{i}", "normal") for i in range(10)], names)

    assert [e["split"] for e in first] == [e["split"] for e in second]
