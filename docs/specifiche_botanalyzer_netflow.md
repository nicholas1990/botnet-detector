# Botnet Detector — Specifiche Implementabili

## 1. Obiettivo

Implementare un detector di botnet **anomaly-based**, basato esclusivamente su dati **NetFlow/IPFIX**, senza ispezione del payload e senza analisi host-based.

Il modello deve rilevare:
- comportamenti anomali di singoli host;
- connessioni anomale;
- gruppi di host con comportamenti simili e coordinati;
- possibili attività di botnet prima, quando possibile, della fase di attacco.

La specifica deriva dal framework descritto nel paper *Botnets: A Heuristic-Based Detection Framework*. Il paper definisce un prototipo chiamato **BotAnalyzer**, implementato come plugin Nfsen con database SQL Server, e usa fingerprint delle comunicazioni e clustering orizzontale per la seconda fase di detection. [Fonte: paper, sez. 4–5]

## 2. Input

### 2.1 Record NetFlow minimo

Ogni flow deve contenere:

```text
src_ip
dst_ip
src_port
dst_port
protocol
bytes
packets
flow_start_time
flow_end_time
```

Questi sono gli attributi utilizzati dal prototipo originale.

### 2.2 Normalizzazione

Per ogni flow calcolare:

```text
duration = flow_end_time - flow_start_time
bpp      = bytes / packets
```

Gestire esplicitamente:
- `packets = 0`;
- durata nulla;
- valori mancanti;
- timestamp non validi.

Non inventare valori mancanti: il flow deve essere scartato o marcato come invalido secondo una policy configurabile.

## 3. Finestra temporale

Il detector opera su una finestra temporale configurabile.

Parametro iniziale consigliato:

```yaml
window:
  duration: 1h
  step: 5m
```

Il paper evidenzia che finestre troppo piccole possono rendere i valori di diversità poco affidabili quando un source IP ha poche connessioni; quindi la durata della finestra deve essere configurabile.

## 4. Heuristics

Le heuristics fondamentali sono:

1. **Unidirectional Flows of Data**
2. **Distinct Source Ports (DSP)**
3. **Distinct Destination Ports (DDP)**
4. **Bytes per Packet (BPP)**
5. **Packets per Flow (PPF)**
6. **Time Between Flows (TBF)**
7. **Flow Duration (FD)**

DSP/DDP, BPP/PPF e TBF/FD devono essere analizzati per protocollo e destination host, secondo il modello del paper.

## 5. Simpson's Diversity Index

Per ogni distribuzione calcolare il Simpson's Diversity Index:

```text
D = Σ p_i²
```

dove `p_i` è la percentuale degli elementi appartenenti all'intervallo `i`.

Quando serve evidenziare la diversità anziché la concentrazione può essere usato l'indice inverso:

```text
D_inverse = 1 - D
```

### 5.1 Binning

Per TBF e FD il paper normalizza i valori usando intervalli da **100 ms**:

```text
rounded_value = floor(value_ms / 100) * 100
```

La granularità deve essere configurabile, mantenendo `100 ms` come default compatibile con il paper.

## 6. Communication Fingerprint

Per ogni coppia:

```text
(src_ip, dst_ip)
```

creare due fingerprint distinti:

```text
TCP fingerprint
UDP fingerprint
```

Ogni fingerprint contiene:

```text
DSP
DDP
BPP
PPF
TBF
FD
```

Esempio logico:

```json
{
  "src_ip": "10.0.0.10",
  "dst_ip": "203.0.113.20",
  "protocol": "TCP",
  "fingerprint": {
    "DSP": 0.12,
    "DDP": 0.03,
    "BPP": 0.18,
    "PPF": 0.05,
    "TBF": 0.02,
    "FD": 0.07
  }
}
```

### 6.1 Protocollo assente

Se nella finestra non esiste traffico per un determinato protocollo, il valore delle caratteristiche del fingerprint deve essere:

```text
-1
```

Questo permette di distinguere:
- assenza di traffico;
- presenza di traffico con bassa diversità.

## 7. First-Pass Detection

La prima fase esegue una **vertical analysis**.

Obiettivo:

```text
flow → connection anomaly → host anomaly
```

### 7.1 Connection Anomalous Score — CAS

Calcolare una media pesata delle componenti del fingerprint:

```text
CAS = weighted_mean(DSP, DDP, BPP, PPF, TBF, FD)
```

I pesi devono essere configurabili:

```yaml
weights:
  DSP: 1.0
  DDP: 1.0
  BPP: 1.0
  PPF: 1.0
  TBF: 1.0
  FD: 1.0
```

Il paper stabilisce che **bassi valori di diversità sono indicativi di comportamento anomalo**.

Per evitare ambiguità di implementazione, definire esplicitamente una funzione di normalizzazione e scoring nel codice/configurazione, invece di assumere implicitamente il significato della scala.

### 7.2 Scaling

Il paper applica un fattore:

```text
1000
```

agli indici di diversità e ai relativi threshold.

Quindi la rappresentazione operativa può essere:

```text
score_scaled = score * 1000
```

## 8. Host Anomalous Score — HAS

Per ogni `src_ip` aggregare i CAS delle connessioni:

```text
HAS = weighted_mean(CAS_1, CAS_2, ..., CAS_n)
```

Il sistema deve inoltre contare:

```text
anomalous_connections
```

per host.

## 9. Thresholds

Il modello originale utilizza tre parametri:

```text
CAST  = Connection Anomalous Score Threshold
HAST  = Host Anomalous Score Threshold
MNACT = Minimum Number of Anomalous Connections Threshold
```

Configurazione:

```yaml
thresholds:
  CAST: <configurable>
  HAST: 950
  MNACT: 70
```

I valori `HAST=950` e `MNACT=70` sono riportati nel paper come configurazioni sperimentali, **non devono essere considerati valori universalmente ottimali**.

Una connection è anomala se:

```text
CAS >= CAST
```

Un host supera il first pass se:

```text
HAS >= HAST
AND
anomalous_connections >= MNACT
```

## 10. Second-Pass Detection — Horizontal Fingerprint Clustering

Dopo il first pass, applicare **Horizontal Fingerprint Clustering (HFC)** alle connessioni anomale.

Obiettivo:

```text
host A ─┐
host B ─┼─> fingerprint simili ─> cluster
host C ─┘
```

Il principio è che comportamenti:
- simili;
- sincronizzati;
- distribuiti su più host

costituiscono evidenza più forte di attività botnet rispetto all'anomalia isolata di un singolo host.

### 10.1 Requisiti del clustering

Il clustering deve:
- usare i communication fingerprints;
- confrontare più host;
- raggruppare fingerprint simili;
- essere parametrico;
- permettere di escludere host che mostrano esclusivamente comportamento di scanning.

L'algoritmo specifico di clustering **non è completamente definito dal paper**, quindi deve essere considerato una decisione progettuale dell'implementazione.

## 11. Scan Detection

Lo scanning è un comportamento importante del ciclo di vita di un bot.

Il detector dovrebbe produrre un indicatore separato:

```text
scan_score
```

e classificare almeno:

```text
NORMAL
POSSIBLE_SCAN
ANOMALOUS
BOTNET_CANDIDATE
```

Lo scan-only non deve automaticamente equivalere a botnet.

Il paper infatti descrive il secondo pass come un meccanismo che può escludere dalla detection gli host puramente scanner.

## 12. Botnet Candidate

Un gruppo può essere classificato come:

```text
BOTNET_CANDIDATE
```

quando sono presenti contemporaneamente:

1. più host;
2. connessioni anomale;
3. fingerprint simili;
4. evidenza di comportamento coordinato;
5. numero sufficiente di connessioni/host secondo threshold configurabili.

Schema:

```text
NetFlow
   ↓
Feature extraction
   ↓
Fingerprint generation
   ↓
First-pass vertical analysis
   ↓
CAS / HAS
   ↓
Anomalous connections
   ↓
Horizontal Fingerprint Clustering
   ↓
Cluster di host simili
   ↓
BOTNET_CANDIDATE
```

## 13. Output

Ogni alert deve contenere almeno:

```json
{
  "timestamp": "...",
  "src_ip": "...",
  "classification": "BOTNET_CANDIDATE",
  "has": 0,
  "anomalous_connections": 0,
  "cluster_id": "...",
  "cluster_size": 0,
  "confidence": 0,
  "evidence": {
    "DSP": 0,
    "DDP": 0,
    "BPP": 0,
    "PPF": 0,
    "TBF": 0,
    "FD": 0
  }
}
```

Il campo `confidence` deve essere chiaramente distinto da TPR/FPR: il paper non definisce una formula di confidence score.

## 14. Whitelist

Implementare una whitelist configurabile per ridurre falsi positivi associati a servizi legittimi.

Il paper cita in particolare servizi come:

```text
DNS
DHCP
VPN
NetBIOS
Kerberos
```

La whitelist deve supportare TTL/revalidation:

```yaml
whitelist:
  enabled: true
  ttl: 30d
```

Evitare il blind-whitelisting permanente: un host legittimo compromesso potrebbe altrimenti nascondere traffico botnet.

## 15. Persistenza

Il sistema deve conservare:

### Raw/normalized flows

```text
src_ip
dst_ip
src_port
dst_port
protocol
bytes
packets
start
end
duration
bpp
```

### Features

```text
DSP
DDP
BPP
PPF
TBF
FD
```

### Fingerprints

```text
src_ip
dst_ip
protocol
window
DSP
DDP
BPP
PPF
TBF
FD
```

### Detection results

```text
CAS
HAS
CAST
HAST
MNACT
anomalous_connections
cluster_id
classification
```

## 16. API minima

Se il detector viene implementato come servizio, esporre almeno:

```text
POST /flows
GET  /hosts/{ip}/score
GET  /hosts/{ip}/fingerprint
GET  /clusters
GET  /alerts
GET  /alerts/{id}
GET  /health
```

## 17. Configurazione

Esempio:

```yaml
detector:
  window_duration: 1h
  window_step: 5m
  tbf_bin_ms: 100
  fd_bin_ms: 100

thresholds:
  CAST: 0
  HAST: 950
  MNACT: 70

weights:
  DSP: 1.0
  DDP: 1.0
  BPP: 1.0
  PPF: 1.0
  TBF: 1.0
  FD: 1.0

clustering:
  enabled: true
  algorithm: configurable
  similarity_threshold: configurable
  min_cluster_size: configurable

whitelist:
  enabled: true
  ttl: 30d
```

`CAST`, `similarity_threshold`, `min_cluster_size` e i pesi devono essere calibrati sul dataset reale.

## 18. Metriche

Il sistema di valutazione deve calcolare:

```text
TPR = TP / (TP + FN)
TNR = TN / (TN + FP)
FPR = FP / (FP + TN)
FNR = FN / (FN + TP)
```

Non utilizzare ROC come unica misura di accuratezza.

Il paper sottolinea che blacklists e ROC sono utili per valutare la sensibilità, ma non sono sufficienti da soli per stabilire l'accuratezza complessiva.

## 19. Test

Implementare almeno:

### Unit test
- parsing NetFlow;
- duration;
- BPP;
- PPF;
- TBF;
- binning 100 ms;
- Simpson index;
- fingerprint generation;
- CAS;
- HAS;
- threshold evaluation.

### Integration test
- flow ingestion → fingerprint;
- fingerprint → first pass;
- first pass → HFC;
- HFC → alert.

### Dataset test
Creare dataset sintetici con:
1. traffico normale;
2. scanning;
3. C&C periodico;
4. traffico coordinato tra più host;
5. botnet con fingerprint simili;
6. botnet con keep-alive molto ridotto.

## 20. Limiti da considerare nell'implementazione

Il paper evidenzia diversi limiti che devono essere esplicitamente documentati:

- con poche connessioni per source IP, gli indici di diversità possono risultare distorti;
- i servizi legittimi possono generare falsi positivi;
- il first pass può produrre un numero molto elevato di anomalie;
- il clustering riduce il numero di detection ma può anche ridurre il TPR;
- il modello è debole nel rilevare bot che si trovano in fase di semplice keep-alive;
- un singolo inter-host flow può non essere valorizzato adeguatamente;
- la validazione tramite blacklist non dimostra da sola che ogni detection sia realmente botnet.

## 21. Future Extensions

Possibili estensioni coerenti con il paper:

- Deep-Vertical Analysis;
- Deep-Horizontal / Wide-Horizontal Analysis;
- correlazione request/response;
- detection di stealth C&C;
- Random Forest;
- streaming algorithms;
- integrazione con honeypot;
- integrazione con signature-based detection;
- eventuale packet inspection per validazione delle detection.

## 22. Nota di implementazione

Questa specifica separa volutamente:

**ciò che il paper definisce**
- NetFlow;
- feature;
- Simpson Diversity Index;
- communication fingerprints;
- CAS/HAS;
- CAST/HAST/MNACT;
- first-pass;
- Horizontal Fingerprint Clustering;
- whitelist;
- metriche di valutazione;

da:

**decisioni che l'implementazione moderna deve ancora definire**
- algoritmo di clustering;
- formula esatta dei pesi;
- definizione operativa di confidence;
- valori ottimali dei threshold;
- database/storage moderni;
- formato API;
- gestione streaming;
- retention;
- deployment.

Queste ultime non devono essere presentate come risultati o specifiche già definite dal paper.
