# Roadmap

Stato di avanzamento rispetto a [`specifiche_botnet_detector.md`](specifiche_botnet_detector.md).
Aggiornare questo file ad ogni passo completato (un commit per passo, vedi git log per i dettagli).

## Fatto

- [x] Setup `.venv` + `requirements.txt` (scapy)
- [x] Contratto `PacketRecord` (`src/capture/parser.py`)
- [x] `compute_work_weight` (`src/analysis/work_weight.py`)
- [x] `StatisticsWindow.update()` (`src/analysis/statistics.py`)
- [x] `compute_behavioural_indicators` (`src/analysis/behavioural.py`) — destinazioni, porte, connections/sec, rapporto SYN/SYN-ACK
- [x] `compute_risk_score` (`src/scoring/risk_score.py`) — punteggio 0-100 + reasons + classificazione NORMAL/SUSPICIOUS/HIGH RISK

## Da fare

- [ ] `parse_packet` — da pacchetto Scapy a `PacketRecord` (`src/capture/parser.py`)
- [ ] `start_capture` — sniffing live con Scapy, richiede privilegi root (`src/capture/sniffer.py`)
- [ ] `Detector.run()` — orchestrazione finestra temporale → statistiche → work weight → risk score (`src/detector.py`)
- [ ] Output console nel formato di specifica (sez. 10)
- [ ] `main.py` — entry point, parsing argomenti (interfaccia, durata finestra)
- [ ] Dataset di test controllato — scenari A (normale) / B (molte connessioni) / C (scanning) (sez. 14)
- [ ] Dashboard opzionale — Flask/FastAPI/Streamlit (sez. 11)

## Evoluzioni future (fuori dalla v1)

- [ ] Rilevamento comportamento anomalo su traffico cifrato via metadati (sez. 16.A)
- [ ] Classificatore ML sulle statistiche raccolte (sez. 16.B)
