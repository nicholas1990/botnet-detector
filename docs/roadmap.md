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
- [x] `parse_packet` (`src/capture/parser.py`) — da pacchetto Scapy a `PacketRecord`, richiede l'IP locale per determinare la direzione
- [x] `start_capture` (`src/capture/sniffer.py`) — wrapper su `scapy.sniff`, filtro `tcp`, richiede privilegi root
- [x] `Detector` (`src/detector.py`) — rotazione finestra basata sul timestamp dei pacchetti, chiama `on_window_complete` con stats/work weight/risk score

## Da fare

- [ ] Output console nel formato di specifica (sez. 10)
- [ ] `main.py` — entry point, parsing argomenti (interfaccia, durata finestra)
- [ ] Dataset di test controllato — scenari A (normale) / B (molte connessioni) / C (scanning) (sez. 14)
- [ ] Dashboard opzionale — Flask/FastAPI/Streamlit (sez. 11)

## Evoluzioni future (fuori dalla v1)

- [ ] Rilevamento comportamento anomalo su traffico cifrato via metadati (sez. 16.A)
- [ ] Classificatore ML sulle statistiche raccolte (sez. 16.B)
