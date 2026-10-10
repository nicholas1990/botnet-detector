# Valutazione su dataset reali

Prima validazione del detector su traffico registrato, per decidere quali
evoluzioni (memoria tra finestre, feature per flow, robustezza del beaconing)
servono davvero. Riproducibile con `python -m evaluation.evaluate` (vedi
README); dataset elencati in [`evaluation/datasets.json`](../evaluation/datasets.json).

Data: 2026-10-08. Finestra: 30s. Whitelist vuota.

## Dataset

| Dataset | Etichetta | Host monitorato | Durata | Finestre |
|---|---|---|---|---|
| CTU-13 scenario 1 (Neris), solo traffico della VM infetta | botnet | 147.32.84.165 | 4.8h | 564 |
| CTU-Normal-20, Windows, browsing HTTPS su siti Alexa top 1000 | normal | 10.0.2.15 | 3.2h | 367 |

L'etichetta è per cattura, non per finestra (vedi docstring di
`evaluation/evaluate.py`).

## Risultati

| | Alert (SUSPICIOUS + HIGH RISK) | Score medio | Score max |
|---|---|---|---|
| Neris (detection rate) | **99.5%** (448 HIGH RISK, 113 SUSPICIOUS) | 63.8 | 89 |
| Normal-20 (false positive rate) | **35.7%** (1 HIGH RISK, 130 SUSPICIOUS) | 26.1 | 61 |

### Cosa fa scattare gli alert

**Neris:** il rapporto SYN/SYN-ACK basso è presente in 559 finestre su 564
(Neris invia spam e la maggior parte delle connessioni SMTP fallisce). In
pratica la detection poggia su un solo indicatore: Neris è un bot rumoroso
e quindi un caso facile, non rappresentativo di un C&C silenzioso.

**Normal-20:** i falsi positivi vengono da due indicatori.

- *Evenly spread destination traffic* (174 finestre). La diversità di
  Simpson degli IP di destinazione ha mediana 0.79 sul browsing normale e
  0.82 su Neris: la soglia 0.8 cade sulla mediana del traffico normale e
  l'indicatore non discrimina. Il browsing verso CDN multiple è
  naturalmente "uniformemente distribuito".
- *Periodic beaconing pattern detected* (68 finestre, regularity index
  1.00). **È un bug, non una taratura:** in tutte le 68 finestre (e nelle
  10 di Neris) il bin dominante degli intervalli è 0ms. Il TBF misura
  connessioni parallele aperte nello stesso istante (il browser apre più
  socket verso lo stesso host), non periodicità.

16 finestre normali sono in alert senza alcun reason: superano la soglia
30 per somma di contributi tutti sotto le rispettive soglie testuali.

### Stima dell'impatto (what-if sugli stessi dati)

Ricalcolando lo score togliendo i contributi dei due indicatori:

| | Attuale | Senza beaconing a 0ms | e senza bonus diversità IP |
|---|---|---|---|
| False positive rate (Normal-20) | 35.7% | 24.8% | **9.0%** |
| Detection rate (Neris) | 99.5% | 99.5% | 99.1% |

I due indicatori costano 27 punti di falsi positivi e non contribuiscono
quasi nulla alla detection su questi dati.

### Periodicità oltre la finestra (punto "memoria tra finestre")

Analisi sull'intera cattura, per coppia (IP, porta): SYN entro 1s
raggruppati in un unico evento, almeno 5 eventi, periodico se il
coefficiente di variazione degli intervalli è < 0.2.

- Neris: 1 destinazione periodica (213.246.53.125:5296, ~177s).
- Normal-20: 2 destinazioni periodiche di traffico legittimo (porta 80,
  ~250s) più una a ~1s.

Il beaconing con periodo > 15s è in effetti invisibile alla finestra da
30s, ma su questi dati la periodicità da sola produrrebbe tanti falsi
positivi quanti veri positivi, come avverte il paper (§6, "Limite
fondamentale").

## Dopo il fix del TBF (2026-10-08)

I SYN verso la stessa destinazione a meno di 1s dal precedente vengono ora
fusi in un unico evento prima di calcolare gli intervalli
(`group_flow_events`, `TBF_MERGE_GAP_SECONDS` in `src/config.py`).

| | Prima | Dopo |
|---|---|---|
| False positive rate (Normal-20) | 35.7% | **27.2%** |
| Detection rate (Neris) | 99.5% | 99.5% |
| Finestre con beaconing (Normal-20 / Neris) | 68 / 10 | 2 / 9 |

La stima what-if era 24.8%: lo scarto viene dalle 2 finestre normali in
cui il beaconing scatta ancora e dai contributi sotto soglia che restano.

**Limite residuo.** Le hit rimaste non sono beaconing C&C: quasi tutte
hanno esattamente 3 eventi (cioè 2 intervalli uguali) a 1-3s, e su Neris
corrispondono a tentativi ripetuti verso host che non rispondono. Due
intervalli uguali sono un'evidenza debole. Alzare il minimo di eventi
(`MIN_FLOWS_PER_DESTINATION_FOR_TBF`) ridurrebbe il rumore, ma con
finestre da 30s restringerebbe ancora di più i periodi osservabili (4
eventi -> periodo massimo 10s): è lo stesso limite che motiva la memoria
tra finestre, da rivalutare con dataset più ampi.

## Ricalibrazione della diversità IP (2026-10-08)

Distribuzione della diversità di Simpson degli IP di destinazione per
finestra:

| | p10 | p25 | p50 | p75 | p90 |
|---|---|---|---|---|---|
| Normal-20 | 0.43 | 0.66 | 0.79 | 0.90 | 0.94 |
| Neris | 0.75 | 0.78 | 0.82 | 0.85 | 0.88 |

Le distribuzioni si sovrappongono: la coda alta del browsing supera
Neris. Varianti provate sugli stessi dati (what-if sul contributo della
sola regola):

| Variante | False positive | Detection | HIGH RISK su Neris |
|---|---|---|---|
| Attuale (contributo continuo) | 27.2% | 99.5% | 76.1% |
| Soglia 0.8 (punti solo sopra soglia) | 22.1% | 99.1% | 60.8% |
| Soglia 0.9 | 18.0% | 99.1% | 18.4% |
| Soglia 0.95 | 13.1% | 99.1% | 17.4% |
| Regola rimossa | 10.1% | 99.1% | 17.4% |
| **Solo con rapporto SYN/SYN-ACK basso** | **10.1%** | **99.3%** | **76.1%** |

Scelta l'ultima: un fan-out uniforme è sospetto quando le connessioni
falliscono (scan, spam), normale quando riescono (browsing su più CDN).
Combina due feature invece di alzare una soglia, come suggerisce il paper
(§12-13). Rimuovere la regola darebbe gli stessi falsi positivi ma
toglierebbe severità ai casi davvero anomali (HIGH RISK su Neris dal 76%
al 17%).

Attenzione: la condizione usa lo stesso indicatore (SYN/SYN-ACK) su cui
già poggia la detection di Neris, quindi la diversità IP diventa un
moltiplicatore di severità, non un segnale indipendente.

Risultato misurato dopo la modifica:

| | Prima | Dopo |
|---|---|---|
| False positive rate (Normal-20) | 27.2% | **11.4%** |
| Detection rate (Neris) | 99.5% | 99.3% |

**Falsi positivi rimasti (42 finestre).** Sono guidati dal conteggio
degli IP di destinazione: in media 22.5 punti su 30 in quelle finestre,
assegnati in modo continuo anche sotto la soglia testuale (24 finestre
sono in alert senza alcun reason). È il candidato naturale per la
prossima ricalibrazione.

## Ricalibrazione del conteggio IP di destinazione (2026-10-08)

Numero di IP di destinazione distinti per finestra:

| | p10 | p25 | p50 | p75 | p90 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| Normal-20 | 7 | 10 | 19 | 30 | 44 | 48 | 83 |
| Neris | 20 | 22 | 23 | 26 | 28 | 30 | 35 |

Il conteggio grezzo qui discrimina al contrario: nella coda alta il
browsing contatta più host di Neris. Con la scala lineare 0→50 IP il
browsing intenso prendeva quasi tutti i 25 punti della regola.

| Variante | False positive | Detection | HIGH RISK su Neris |
|---|---|---|---|
| Attuale (lineare 0→50 IP) | 11.4% | 99.3% | 76.1% |
| Regola rimossa | 0.0% | 98.8% | 8.2% |
| Punti solo sopra 50 IP | 4.4% | 98.8% | 8.2% |
| Rampa 30→100 IP | 1.1% | 98.8% | 8.3% |
| Rampa 50→150 IP | 0.0% | 98.8% | 8.2% |
| Solo con rapporto SYN/SYN-ACK basso | 0.3% | 99.1% | 76.1% |
| **Ibrida: fallite 0→50, riuscite 50→150** | **0.3%** | **99.1%** | **76.1%** |

Scelta l'ibrida. Ha gli stessi numeri della variante condizionata al
rapporto SYN/SYN-ACK, ma non rende la regola cieca a un fan-out enorme con
connessioni riuscite (es. flood HTTP, click fraud): oltre 50 IP i punti
crescono comunque, fino al massimo a 150 (`SUCCESSFUL_FAN_OUT_IPS_SCALE`).
Con connessioni riuscite il reason compare solo oltre 100 IP
(`LARGE_SUCCESSFUL_FAN_OUT_IPS_THRESHOLD`), cioè quando la regola assegna
almeno metà dei punti; prima scattava in 17 finestre normali che lo score
non considerava anomale.

Risultato misurato:

| | Prima | Dopo |
|---|---|---|
| False positive rate (Normal-20) | 11.4% | **0.3%** (1 finestra su 367) |
| Detection rate (Neris) | 99.3% | 99.1% |
| Score medio Normal-20 | 16.5 | 6.1 |

Effetto sugli scenari sintetici: lo scenario B (40 connessioni riuscite
verso host diversi) passa da SUSPICIOUS (43) a NORMAL (23). Coerente con la
sua definizione di "connessioni legittime"; l'ordinamento A < B < C
richiesto dalle specifiche (sez. 14) resta valido (6 < 23 < 98).

**Attenzione al sovradattamento.** Dopo tre ricalibrazioni sugli stessi
due dataset, 0.3% e 99.1% sono numeri di training, non di test: le soglie
sono state scelte guardando proprio queste catture. Inoltre la severità
(HIGH RISK) e buona parte della detection dipendono ora dal rapporto
SYN/SYN-ACK. Un bot che completa le connessioni (C&C HTTPS, beaconing
silenzioso) passerebbe con pochi punti. Il passo successivo
indispensabile è validare su catture nuove, mai usate per la taratura.

## Validazione su catture nuove (2026-10-10)

Soglie invariate rispetto alle ricalibrazioni precedenti: nessun parametro
è stato toccato dopo aver visto questi dati.

### Dataset

Tutte le catture pubbliche Stratosphere (https://mcfp.felk.cvut.cz/publicDatasets/)
che entrano nei limiti pratici: 398 PCAP scaricati (47GB), manifest
generato con `python -m evaluation.build_manifest` in
[`evaluation/stratosphere.json`](../evaluation/stratosphere.json).

- **Escluse a priori:** catture di malware sopra i 500MB (87, circa
  420GB), catture normali con solo DNS o quasi vuote, CTU-Normal-12
  (filtrata senza la porta 80), dataset CTU-Mixed-* (senza etichetta per
  cattura), spezzoni duplicati e la cattura normale dello scenario
  CTU-13 9.
- **Scartate dal generatore** perché senza un host monitorato chiaramente
  dominante: 63 catture di malware e CTU-Normal-18.
- **Restano:**
  - 300 catture di malware dal 2011 al 2022, di cui 289 con traffico TCP
    dell'host infetto. Le famiglie più rappresentate: TrickBot, WannaCry e
    NotPetya, Dridex, Zbot, Emotet, Sality, Kelihos, Bunitu, Locky, oltre
    agli scenari CTU-13 non usati per la taratura.
  - 15 catture normali.

Riproducibile con
`python -m evaluation.evaluate --manifest evaluation/stratosphere.json -j 10`
(circa 1h su 10 core).

### Risultati complessivi (split holdout)

| | Per finestra | Per cattura |
|---|---|---|
| Detection | 39.2% di 3.43M finestre | 66.8% di 289 (almeno un alert) |
| False positive | **8.0%** di 4176 finestre | 80.0% di 15 (almeno un alert) |

Sui dati di taratura gli stessi numeri erano 99.1% e 0.3%: il
sovradattamento temuto è confermato. Le metriche aggregate vanno però lette
con cautela:

- le catture di malware durano da pochi minuti a 72 giorni, quindi il tasso
  per finestra è dominato dalle catture lunghe (le 10 più lunghe sono il
  29% delle finestre);
- "almeno un alert" è un criterio debole su catture di ore.

Distribuzione per cattura del tasso di alert:

| | p25 | p50 | p75 | p90 | catture con alert > 1% |
|---|---|---|---|---|---|
| Normali | 0.3% | 2.3% | 13.5% | 76.3% | 11/15 |
| Malware | 0.0% | 1.1% | 57.5% | 98.9% | 146/289 |

### Falsi positivi: dipendono dal tipo di host

| Tipo di cattura normale | False positive (finestre) |
|---|---|
| Navigazione interattiva Windows/Linux (11 catture) | **1.8%** |
| Navigazione automatica top-1000 Alexa/Quantcast da Kali (Normal-21, 22, 32) | 36.6% |
| P2P con Deluge (Normal-7) | 53.5% |

- **Crawler.** Normal-21, 22 e 32 visitano in sequenza centinaia di
  siti: oltre 100 IP di destinazione per finestra con connessioni
  riuscite, quindi scatta il ramo "fan-out riuscito molto ampio" della
  regola sul conteggio IP, insieme alla frequenza di connessione. È il
  comportamento che quel ramo vuole cogliere (flood, click fraud), e senza
  contenuto applicativo è indistinguibile.
- **P2P.** Normal-7 ha molte connessioni fallite verso molte porte: per gli
  indicatori del detector è uno scan. È il falso positivo atteso
  dall'analisi dello stato dell'arte; serve una whitelist o una feature
  dedicata.
- **Navigazione interattiva.** 1.8%, più dello 0.3% di Normal-20 ma
  nello stesso ordine di grandezza.

### Detection: la dipendenza dal rapporto SYN/SYN-ACK

Dividendo le catture di malware in base alla quota di finestre con
rapporto SYN/SYN-ACK basso:

| Catture di malware | Catture | Rilevate (alert > 1%) |
|---|---|---|
| Rumorose (SYN/SYN-ACK basso in ≥ 20% delle finestre) | 94 | **94 (100%)** |
| Silenziose (connessioni per lo più riuscite) | 195 | **52 (27%)**, alert mediano 0.0% |

Questa è la misura del limite previsto in "Attenzione al sovradattamento".
Il detector rileva bene ciò che fallisce le connessioni:
- worm che scansionano SMB, come WannaCry e NotPetya (alert mediano 95%);
- spam bot come Kelihos, Donbot e Neris (scenario CTU-13 2: 96.8%);
- Sality e Upatre.

Non vede invece i bot con C&C su connessioni riuscite:
- TrickBot (alert mediano 1.1%);
- Emotet, Locky e Bunitu (circa 0%);
- buona parte dei trojan bancari.

Nelle 52 catture silenziose rilevate, il beaconing è il reason più
frequente in 8: la periodicità entro la finestra di 30s contribuisce, ma
non abbastanza. Le catture silenziose non rilevate hanno score medio
mediano 6.5 e massimo mediano 20: non sono vicine alla soglia, quindi
abbassarla non basterebbe.

### Cosa cambia per la roadmap

1. **Il limite principale è strutturale, non di taratura.** Su 195 bot
   silenziosi il detector per finestra non ha segnale. Servono le feature
   indicate come mancanti dall'analisi dello stato dell'arte:
   - memoria tra finestre (beaconing con periodo > 15s, persistenza
     verso la stessa destinazione);
   - feature per flow (durata, byte, regolarità delle dimensioni).

   Questi dati giustificano ora quel lavoro, che prima non era giustificato
   (vedi conclusioni sotto).
2. **Non ritarare sulle catture di holdout.** Ogni ritocco va fatto su un
   sottoinsieme separato e verificato sul resto, altrimenti si ripete il
   sovradattamento misurato qui.
3. **Falsi positivi:** P2P e crawler vanno gestiti come casi d'uso
   distinti (whitelist per applicazione, o contesto dell'host), non con
   soglie globali.

## Conclusioni per la roadmap

1. ~~**Correggere il TBF (priorità alta, costo basso).**~~ Fatto: vedi
   "Dopo il fix del TBF" sopra.
2. ~~**Ricalibrare la diversità IP.**~~ Fatto: vedi "Ricalibrazione della
   diversità IP" sopra. Fatto anche il conteggio degli IP di destinazione
   (vedi "Ricalibrazione del conteggio IP di destinazione").
3. **Memoria tra finestre: non giustificata dai primi due dataset**, ma
   giustificata dalla validazione su catture nuove (vedi sopra: 27% dei
   bot silenziosi rilevati). Neris è già
   rilevato senza; la periodicità lunga, da sola, non discrimina. Ha senso
   solo insieme a feature complementari (dimensioni dei flow simili,
   punto "feature per flow") e va rivalutata su un bot silenzioso.
4. ~~**Allargare i dataset.**~~ Fatto: vedi "Validazione su catture
   nuove". Testo originale: un solo bot rumoroso e una sola cattura normale
   non bastano: servono un bot con C&C a basso rumore (es. HTTPS
   beaconing, dataset Stratosphere più recenti) e più catture normali
   (CTU-Normal-21/22, Linux) per stimare il false positive rate in modo
   meno dipendente dal singolo host.
