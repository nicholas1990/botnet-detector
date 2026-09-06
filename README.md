# Botnet Detector

Sistema host-based in Python per l'analisi del traffico di rete di una singola
macchina, orientato all'individuazione di comportamenti anomali compatibili
con scanning o attività botnet.

Basato sul **TCP Work Weight** descritto nel paper *An Algorithm for Botnet
Detection* (Odai Marashdeh), adattato dal contesto di monitoraggio multi-host
a quello di un singolo host, ed esteso con analisi comportamentale
(destinazioni uniche, porte uniche, frequenza connessioni, rapporto
SYN/SYN-ACK), Simpson Diversity Index, Time Between Flows (beaconing) e
whitelist TCP con TTL, oltre al Risk Score.

Le specifiche implementate sono in [`docs/specifiche_botnet_detector.md`](docs/specifiche_botnet_detector.md);
alcune estensioni si ispirano a [`docs/specifiche_botanalyzer_netflow.md`](docs/specifiche_botanalyzer_netflow.md)
(NetFlow/BotAnalyzer), adattate al modello single-host attuale — vedi
[`docs/roadmap.md`](docs/roadmap.md) per lo stato di avanzamento completo.

## Struttura del progetto

```text
botnet-detector/
│
├── README.md
├── requirements.txt
├── whitelist.example.json
│
├── docs/
│   ├── specifiche_botnet_detector.md
│   ├── specifiche_botanalyzer_netflow.md
│   └── roadmap.md
│
├── src/
│   ├── main.py
│   ├── config.py
│   ├── detector.py
│   │
│   ├── capture/
│   │   ├── sniffer.py
│   │   └── parser.py
│   │
│   ├── filtering/
│   │   └── whitelist.py
│   │
│   ├── analysis/
│   │   ├── statistics.py
│   │   ├── work_weight.py
│   │   ├── behavioural.py
│   │   ├── diversity.py
│   │   └── timing.py
│   │
│   ├── scoring/
│   │   └── risk_score.py
│   │
│   └── reporting/
│       ├── console.py
│       └── persistence.py
│
├── tests/
│   ├── fixtures/
│   │   └── scenarios.py
│   ├── test_main.py
│   ├── test_detector.py
│   ├── test_sniffer.py
│   ├── test_parser.py
│   ├── test_statistics.py
│   ├── test_work_weight.py
│   ├── test_behavioural.py
│   ├── test_diversity.py
│   ├── test_timing.py
│   ├── test_whitelist.py
│   ├── test_risk_score.py
│   ├── test_console.py
│   ├── test_persistence.py
│   ├── test_dashboard_app.py
│   └── test_scenarios.py
│
├── data/
│   └── samples/
│
└── dashboard/
    └── app.py
```

## Requisiti

- Python 3.x
- [Scapy](https://scapy.net/) per la cattura dei pacchetti
- Privilegi di amministratore/root per la cattura del traffico

```bash
pip install -r requirements.txt
```

## Uso

```bash
sudo python -m src.main [-i INTERFACE] [-w WINDOW] [--dashboard-db PATH]
```

Whitelist opzionale: copia `whitelist.example.json` in `whitelist.json`
(ignorato da git) nella root del progetto e personalizza le voci — vedi
`docs/roadmap.md` sez. whitelist per il formato.

Dashboard opzionale: avvia il detector con `--dashboard-db dashboard.db` per
scrivere i risultati per finestra su SQLite, poi in un secondo terminale
(senza privilegi elevati):

```bash
streamlit run dashboard/app.py
```

## Stato del progetto

Cattura, parsing, statistiche, indicatori comportamentali (inclusi diversità
e beaconing), Risk Score, whitelist TCP, report console e dashboard opzionale
(Streamlit, dati condivisi via SQLite) sono implementati e testati
(`pytest`). Supporto UDP resta da fare — vedi [`docs/roadmap.md`](docs/roadmap.md).

## Sicurezza ed etica

Strumento di monitoraggio difensivo. Eventuali test di scanning vanno
eseguiti esclusivamente su macchine proprie o in un laboratorio autorizzato.
