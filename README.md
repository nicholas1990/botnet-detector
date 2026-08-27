# Botnet Detector

Sistema host-based in Python per l'analisi del traffico di rete di una singola
macchina, orientato all'individuazione di comportamenti anomali compatibili
con scanning o attività botnet.

Basato sul **TCP Work Weight** descritto nel paper *An Algorithm for Botnet
Detection* (Odai Marashdeh), adattato dal contesto di monitoraggio multi-host
a quello di un singolo host, ed esteso con analisi comportamentale
(destinazioni uniche, porte uniche, frequenza connessioni, rapporto
SYN/SYN-ACK) e Risk Score.

Le specifiche complete sono in [`docs/specifiche_botnet_detector.md`](docs/specifiche_botnet_detector.md).

## Struttura del progetto

```text
botnet-detector/
│
├── README.md
├── requirements.txt
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
│   ├── analysis/
│   │   ├── statistics.py
│   │   ├── work_weight.py
│   │   └── behavioural.py
│   │
│   └── scoring/
│       └── risk_score.py
│
├── tests/
│   ├── test_work_weight.py
│   ├── test_statistics.py
│   └── test_risk_score.py
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

## Uso (WIP)

```bash
sudo python src/main.py
```

## Stato del progetto

Scaffolding iniziale — la logica di cattura, analisi e scoring è da
implementare secondo le specifiche.

## Sicurezza ed etica

Strumento di monitoraggio difensivo. Eventuali test di scanning vanno
eseguiti esclusivamente su macchine proprie o in un laboratorio autorizzato.
