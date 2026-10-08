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

## Conclusioni per la roadmap

1. ~~**Correggere il TBF (priorità alta, costo basso).**~~ Fatto: vedi
   "Dopo il fix del TBF" sopra.
2. ~~**Ricalibrare la diversità IP.**~~ Fatto: vedi "Ricalibrazione della
   diversità IP" sopra. Prossimo candidato: il conteggio degli IP di
   destinazione.
3. **Memoria tra finestre: non giustificata da questi dati.** Neris è già
   rilevato senza; la periodicità lunga, da sola, non discrimina. Ha senso
   solo insieme a feature complementari (dimensioni dei flow simili,
   punto "feature per flow") e va rivalutata su un bot silenzioso.
4. **Allargare i dataset.** Un solo bot rumoroso e una sola cattura normale
   non bastano: servono un bot con C&C a basso rumore (es. HTTPS
   beaconing, dataset Stratosphere più recenti) e più catture normali
   (CTU-Normal-21/22, Linux) per stimare il false positive rate in modo
   meno dipendente dal singolo host.
