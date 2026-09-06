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
- [x] Test end-to-end su scenari combinati (`scenario_d_beaconing_and_port_sweep` in `tests/fixtures/scenarios.py`): due anomalie indipendenti (beaconing su un host, port sweep verticale su un altro) nella stessa finestra, verificando che entrambe producano un reason e che nessuna mascheri l'altra. Aggiunto anche un test di composizione whitelist + scoring: lo scenario C (di per sé HIGH RISK) diventa NORMAL, reasons vuoto, se le porte sondate sono interamente whitelisted — replica a livello di `StatisticsWindow`/`compute_risk_score` il filtro che `Detector.process_packet` applica a monte (quel filtro end-to-end è già coperto separatamente in `tests/test_detector.py`)
- [x] Simpson Diversity Index (`src/analysis/diversity.py`) — `simpson_index`/`diversity_index`, ispirato a [`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 5
- [x] `StatisticsWindow` — frequenza per destinazione/porta (`Counter`) e porte per singola destinazione (`ports_by_destination`), base per DSP/DDP
- [x] `compute_behavioural_indicators` esteso con `destination_ip_diversity`, `destination_port_diversity` e `single_target_port_diversity` (DDP per-coppia src/dst)
- [x] `compute_risk_score` — bonus additivo per fan-out orizzontale (diversità IP, scan di rete) e port sweep verticale su singola destinazione
- [x] Report console — visualizzazione dei due indici di diversità
- [x] Time Between Flows (TBF) (`src/analysis/timing.py`, `compute_beaconing_score` in `src/analysis/behavioural.py`) — binning a 100ms degli intervalli tra SYN consecutivi verso la stessa destinazione, concentrazione di Simpson come indice di regolarità/beaconing, bonus nel risk score e riga dedicata nel report console ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 4-5)
- [x] Whitelist servizi legittimi TCP (`src/filtering/whitelist.py`, `whitelist.example.json`) — entry per IP/porta/coppia con TTL esplicito (`added_at`/`ttl_days`, default 30gg), niente auto-apprendimento; traffico whitelisted escluso a monte in `Detector.process_packet` prima che entri nelle statistiche. Limitata a TCP finché la cattura resta TCP-only (vedi "Supporto UDP" sotto); DNS/DHCP/NTP restano fuori scope perché su UDP non vengono catturati a prescindere ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md) sez. 14)
- [x] Dashboard opzionale (sez. 11) — Streamlit, `dashboard/app.py` a livello radice, dati condivisi via SQLite (opzione (b)):
  - **Tecnologia: Streamlit** (puro Python, niente secondo linguaggio/toolchain, primitive già pronte per serie temporali e refresh live). Scartate React Native (pensato per app mobile, irrilevante per un tool locale che richiede root sulla stessa macchina monitorata) e Angular (SPA multi-vista, sproporzionato per un'unica schermata con ~6 metriche). FastAPI + frontend statico minimale resta l'alternativa se in futuro servirà più controllo sull'interfaccia di quanto Streamlit offra.
  - **Posizione: `dashboard/` a livello radice** (sibling di `src/`/`tests/`/`docs/`), non dentro `src/`. Non è un componente della pipeline di rilevamento (capture→analysis→scoring→reporting): è una seconda superficie eseguibile a sé, avviata con comando proprio (`streamlit run dashboard/app.py`), concettualmente più vicina a `main.py` (entry point) che a `reporting/console.py` (funzione pura chiamata da `Detector`). Importa da `src.*` come fa `main.py`.
  - **Meccanismo di condivisione dati: opzione (b).** `Detector.run()` resta un loop bloccante (`scapy.sniff`) in un processo separato, lanciato con `sudo` via `main.py --dashboard-db PATH` (opt-in: se l'opzione non è passata, il comportamento è invariato — solo report console); ad ogni finestra chiusa `src/reporting/persistence.py` scrive il risultato (`score`, `status`, `reasons`, `indicators`, conteggi principali, timestamp) su SQLite in WAL mode. La dashboard Streamlit gira come processo distinto, senza privilegi elevati, e rilegge periodicamente (`fetch_recent_results`, fragment Streamlit con `run_every`) per aggiornare la UI.
    - **Perché (b):** principio del privilegio minimo — solo il processo di cattura gira come root; il codice web-facing (Streamlit, superficie di attacco più ampia perché espone una porta) resta completamente disaccoppiato e non privilegiato. Beneficio secondario: i due processi hanno cicli di vita indipendenti (si può riavviare la dashboard senza toccare la cattura, e viceversa) e lo storico delle finestre passate resta disponibile su disco.
    - **Alternative valutate e scartate:** (a) thread in background nello stesso processo con store in memoria — scartata perché costringerebbe l'intero server web a girare come root; variante di (a) con drop dei privilegi dopo l'apertura del socket di cattura — scartata perché il comportamento del drop dei privilegi è fragile e diverso tra Linux/macOS (BPF)/Windows (Npcap), e romperebbe la scelta deliberatamente cross-platform di `src/capture/sniffer.py`; (c) processo `main.py` separato con API/socket locale interrogato dalla dashboard — scartata perché aggiunge complessità sproporzionata dato che la granularità delle finestre (30s) rende il polling su file/DB già adeguato; (d) broker esterno tipo Redis pub/sub — scartato come dipendenza esterna sproporzionata per uno strumento locale single-host.

## Da fare

Nessuna voce aperta nella v1 oltre alle evoluzioni future sotto — vedi le priorità concordate per i prossimi passi (test end-to-end su scenari combinati, poi supporto UDP).

## Evoluzioni future (fuori dalla v1)

- [ ] **Supporto UDP nella cattura** — oggi il sistema è deliberatamente TCP-only (`specifiche_botnet_detector.md` sez. 2/4: "identificare i pacchetti TCP"), quindi DNS/DHCP/NTP/Kerberos-UDP sono del tutto invisibili al detector, whitelist o meno. Richiede: estendere il filtro BPF in `src/capture/sniffer.py` (oggi `"tcp"`) a `"tcp or udp"`, un ramo di parsing UDP in `src/capture/parser.py` (niente flag SYN/FIN/RST, quindi il TCP Work Weight resta TCP-specifico per definizione), e una `StatisticsWindow` che distingua i due protocolli. Gli indicatori già protocol-agnostic (Simpson Diversity Index, `single_target_port_diversity`, TBF/beaconing — non dipendono dai flag TCP) si estenderebbero naturalmente al traffico UDP, utile per rilevare C&C su DNS tunneling o beaconing via NTP. Richiede un redesign del layer di cattura/statistiche; non si innesta incrementalmente sul codice attuale.
- [ ] Rilevamento comportamento anomalo su traffico cifrato via metadati (sez. 16.A)
- [ ] Classificatore ML sulle statistiche raccolte (sez. 16.B)
- [ ] Architettura NetFlow/IPFIX multi-host con Horizontal Fingerprint Clustering ([`specifiche_botanalyzer_netflow.md`](specifiche_botanalyzer_netflow.md)) — pienamente implementabile ma richiede un redesign del layer di cattura (NetFlow invece di sniffing locale) e correlazione tra più host; non si innesta incrementalmente sul codice attuale
