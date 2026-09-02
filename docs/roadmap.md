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
- [x] Dataset di test controllato (`tests/fixtures/scenarios.py`, `tests/test_scenarios.py`) — scenari A/B/C (sez. 14): A=NORMAL, B=SUSPICIOUS, C=HIGH RISK, con punteggio crescente A < B < C. Nota: nello scenario C il conteggio degli host "aperti" (`open_hosts`) è globale sulle due porte simulate, non per-porta — sufficiente per verificare "quasi tutto respinto", non per un controllo preciso "N host aperti per ciascuna porta" (vedi commento in `scenarios.py`)
- [x] Simpson Diversity Index (`src/analysis/diversity.py`) — `simpson_index`/`diversity_index`, ispirato a [`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 5
- [x] `StatisticsWindow` — frequenza per destinazione/porta (`Counter`) e porte per singola destinazione (`ports_by_destination`), base per DSP/DDP
- [x] `compute_behavioural_indicators` esteso con `destination_ip_diversity`, `destination_port_diversity` e `single_target_port_diversity` (DDP per-coppia src/dst)
- [x] `compute_risk_score` — bonus additivo per fan-out orizzontale (diversità IP, scan di rete) e port sweep verticale su singola destinazione
- [x] Report console — visualizzazione dei due indici di diversità
- [x] Time Between Flows (TBF) (`src/analysis/timing.py`, `compute_beaconing_score` in `src/analysis/behavioural.py`) — binning a 100ms degli intervalli tra SYN consecutivi verso la stessa destinazione, concentrazione di Simpson come indice di regolarità/beaconing, bonus nel risk score e riga dedicata nel report console ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 4-5)
- [x] Whitelist servizi legittimi TCP (`src/whitelist.py`, `whitelist.example.json`) — entry per IP/porta/coppia con TTL esplicito (`added_at`/`ttl_days`, default 30gg), niente auto-apprendimento; traffico whitelisted escluso a monte in `Detector.process_packet` prima che entri nelle statistiche. Limitata a TCP finché la cattura resta TCP-only (vedi "Supporto UDP" sotto); DNS/DHCP/NTP restano fuori scope perché su UDP non vengono catturati a prescindere ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 14)

## Da fare

- [ ] Dashboard opzionale — Flask/FastAPI/Streamlit (sez. 11)

## Evoluzioni future (fuori dalla v1)

- [ ] **Supporto UDP nella cattura** — oggi il sistema è deliberatamente TCP-only (`specifiche_botnet_detector.md` sez. 2/4: "identificare i pacchetti TCP"), quindi DNS/DHCP/NTP/Kerberos-UDP sono del tutto invisibili al detector, whitelist o meno. Richiede: estendere il filtro BPF in `src/capture/sniffer.py` (oggi `"tcp"`) a `"tcp or udp"`, un ramo di parsing UDP in `src/capture/parser.py` (niente flag SYN/FIN/RST, quindi il TCP Work Weight resta TCP-specifico per definizione), e una `StatisticsWindow` che distingua i due protocolli. Gli indicatori già protocol-agnostic (Simpson Diversity Index, `single_target_port_diversity`, TBF/beaconing — non dipendono dai flag TCP) si estenderebbero naturalmente al traffico UDP, utile per rilevare C&C su DNS tunneling o beaconing via NTP. Richiede un redesign del layer di cattura/statistiche; non si innesta incrementalmente sul codice attuale.
- [ ] Rilevamento comportamento anomalo su traffico cifrato via metadati (sez. 16.A)
- [ ] Classificatore ML sulle statistiche raccolte (sez. 16.B)
- [ ] Architettura NetFlow/IPFIX multi-host con Horizontal Fingerprint Clustering ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md)) — pienamente implementabile ma richiede un redesign del layer di cattura (NetFlow invece di sniffing locale) e correlazione tra più host; non si innesta incrementalmente sul codice attuale
