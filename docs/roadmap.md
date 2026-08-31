# Roadmap

Stato di avanzamento rispetto a [`specifiche_botnet_detector.md`](specifiche_botnet_detector.md).
Aggiornare questo file ad ogni passo completato (un commit per passo, vedi git log per i dettagli).

Alcune voci sono estensioni ispirate a [`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md)
e adattate al modello single-host attuale; l'architettura NetFlow/multi-host completa di quel
documento resta una evoluzione separata (vedi "Evoluzioni future").

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
- [x] Output console nel formato di specifica (`src/reporting/console.py`, sez. 10)
- [x] `main.py` — entry point, parsing argomenti (interfaccia, durata finestra), risoluzione IP locale via Scapy
- [x] Dataset di test controllato (`tests/fixtures/scenarios.py`, `tests/test_scenarios.py`) — scenari A/B/C (sez. 14): A=NORMAL, B=SUSPICIOUS, C=HIGH RISK, con punteggio crescente A < B < C
- [x] Simpson Diversity Index (`src/analysis/diversity.py`) — `simpson_index`/`diversity_index`, ispirato a [`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 5
- [x] `StatisticsWindow` — frequenza per destinazione/porta (`Counter`) e porte per singola destinazione (`ports_by_destination`), base per DSP/DDP
- [x] `compute_behavioural_indicators` esteso con `destination_ip_diversity`, `destination_port_diversity` e `single_target_port_diversity` (DDP per-coppia src/dst)
- [x] `compute_risk_score` — bonus additivo per fan-out orizzontale (diversità IP, scan di rete) e port sweep verticale su singola destinazione
- [x] Report console — visualizzazione dei due indici di diversità

## Da fare

- [ ] Dashboard opzionale — Flask/FastAPI/Streamlit (sez. 11)
- [ ] Time Between Flows (TBF) — diversità di regolarità temporale tra connessioni, per rilevare beaconing C&C periodico ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 4-5)
- [ ] Whitelist servizi legittimi (DNS/DHCP/NTP/Kerberos/VPN) con TTL, per ridurre falsi positivi ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 14)

## Evoluzioni future (fuori dalla v1)

- [ ] Rilevamento comportamento anomalo su traffico cifrato via metadati (sez. 16.A)
- [ ] Classificatore ML sulle statistiche raccolte (sez. 16.B)
- [ ] Architettura NetFlow/IPFIX multi-host con Horizontal Fingerprint Clustering ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md)) — pienamente implementabile ma richiede un redesign del layer di cattura (NetFlow invece di sniffing locale) e correlazione tra più host; non si innesta incrementalmente sul codice attuale
