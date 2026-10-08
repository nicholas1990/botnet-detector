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

## Conclusioni per la roadmap

1. **Correggere il TBF (priorità alta, costo basso).** Raggruppare i SYN
   ravvicinati (connessioni parallele, ritrasmissioni) prima di calcolare
   gli intervalli. Oggi l'indicatore misura altro da quello che dichiara.
2. **Ricalibrare la diversità IP.** Soglia e peso attuali non separano
   browsing e bot. Da valutare: alzare la soglia, usarla solo in
   combinazione con un rapporto SYN/SYN-ACK basso, o rimuovere il
   contributo continuo sotto soglia.
3. **Memoria tra finestre: non giustificata da questi dati.** Neris è già
   rilevato senza; la periodicità lunga, da sola, non discrimina. Ha senso
   solo insieme a feature complementari (dimensioni dei flow simili,
   punto "feature per flow") e va rivalutata su un bot silenzioso.
4. **Allargare i dataset.** Un solo bot rumoroso e una sola cattura normale
   non bastano: servono un bot con C&C a basso rumore (es. HTTPS
   beaconing, dataset Stratosphere più recenti) e più catture normali
   (CTU-Normal-21/22, Linux) per stimare il false positive rate in modo
   meno dipendente dal singolo host.
