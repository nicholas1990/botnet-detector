# Specifiche — Host-Based Network Anomaly / Botnet Detector

## 1. Obiettivo

Realizzare un sistema host-based in Python capace di osservare il traffico di rete generato/ricevuto da una singola macchina e individuare comportamenti anomali compatibili con attività di scanning o possibile botnet.

Il progetto prende come riferimento l'algoritmo descritto nel paper *An Algorithm for Botnet Detection*, in particolare il **TCP Work Weight**, adattandolo dal contesto di monitoraggio di rete a quello di un singolo host.

> Nota: il paper originale utilizza anche la correlazione tra più host appartenenti a canali IRC. Questa parte non viene replicata integralmente nel progetto host-based; viene invece mantenuta l'idea di analizzare statistiche TCP e anomalie comportamentali.

---

## 2. Funzionalità principali

Il programma deve:

1. catturare il traffico di rete del computer;
2. identificare i pacchetti TCP;
3. mantenere statistiche per host/connessione;
4. contare:
   - SYN inviati;
   - SYN-ACK ricevuti;
   - FIN inviati;
   - RESET ricevuti;
   - pacchetti totali inviati;
   - pacchetti totali ricevuti;
5. calcolare il **TCP Work Weight**;
6. analizzare ulteriori indicatori comportamentali;
7. assegnare un **Risk Score**;
8. classificare il comportamento come:
   - `NORMAL`
   - `SUSPICIOUS`
   - `HIGH RISK`
9. mostrare gli eventi sospetti in console e/o dashboard.

Il paper definisce il Work Weight come:

`w = (Ss + Fs + Rr) / Tsr`

dove vengono considerati pacchetti TCP di controllo rispetto al totale dei pacchetti TCP.

---

## 3. Architettura

```text
                RETE
                  |
                  v
        +-------------------+
        | Packet Capture    |
        |     (Scapy)       |
        +---------+---------+
                  |
                  v
        +-------------------+
        | Packet Parser     |
        +---------+---------+
                  |
                  v
        +-------------------+
        | Statistics Engine |
        +---------+---------+
                  |
          +-------+-------+
          |               |
          v               v
   Work Weight       Behavioural
     Analysis          Analysis
          |               |
          +-------+-------+
                  |
                  v
        +-------------------+
        |   Risk Scoring    |
        +---------+---------+
                  |
                  v
        +-------------------+
        | Alert / Dashboard |
        +-------------------+
```

---

## 4. Raccolta del traffico

La prima versione può utilizzare **Scapy** per catturare i pacchetti.

Il sistema deve analizzare il traffico del solo host monitorato.

Per ogni pacchetto TCP interessano principalmente:

- IP sorgente;
- IP destinazione;
- porta sorgente;
- porta destinazione;
- flag TCP;
- dimensione del pacchetto;
- timestamp;
- direzione del traffico.

Non è necessario analizzare il payload applicativo per la parte principale del progetto.

---

## 5. Statistiche TCP

Per ogni finestra temporale devono essere mantenuti almeno:

```text
syn_sent
syn_ack_received
fin_sent
rst_received
packets_sent
packets_received
```

Statistiche aggiuntive consigliate:

```text
unique_destination_ips
unique_destination_ports
connections_per_second
bytes_sent
bytes_received
```

Queste statistiche permettono di distinguere meglio un normale utilizzo della rete da un possibile comportamento di scanning.

---

## 6. TCP Work Weight

Implementare il Work Weight descritto nel paper.

Formula:

```text
work_weight = (syn_sent + fin_sent + rst_received) / total_tcp_packets
```

Il valore deve essere rappresentato anche in percentuale:

```text
work_weight_percent = work_weight * 100
```

Esempio:

```text
SYN sent:       80
FIN sent:       10
RST received:   90
TCP packets:   200

Work Weight = (80 + 10 + 90) / 200
            = 0.90
            = 90%
```

Un valore elevato deve essere considerato un indicatore di possibile anomalia, ma **non deve essere considerato automaticamente una prova di infezione**.

Il paper osserva infatti che valori elevati possono avere anche altre cause, tra cui scanner, client senza server e alcuni comportamenti P2P.

---

## 7. Analisi comportamentale

Per rendere il progetto più interessante rispetto alla semplice implementazione della formula, aggiungere indicatori basati sul comportamento.

### 7.1 Numero di destinazioni

Contare quanti IP differenti vengono contattati durante una finestra temporale.

Esempio:

```text
10 connessioni → comportamento probabilmente normale
500 destinazioni → possibile scanning
```

### 7.2 Numero di porte

Contare quante porte differenti vengono contattate.

Un numero elevato di porte può essere un indicatore di probing/scanning.

### 7.3 Frequenza delle connessioni

Calcolare:

```text
connections_per_second
```

Un aumento improvviso può contribuire al Risk Score.

### 7.4 Rapporto SYN / SYN-ACK

Confrontare i SYN inviati con le risposte SYN-ACK ricevute.

Un host che invia moltissimi SYN e riceve poche risposte può presentare un comportamento compatibile con scanning.

---

## 8. Risk Score

Creare un punteggio da `0` a `100`.

Esempio concettuale:

```text
Risk Score
|
|-- Work Weight elevato
|-- molte destinazioni IP
|-- molte porte
|-- elevata frequenza di connessioni
|-- rapporto SYN/SYN-ACK anomalo
```

Possibile classificazione:

```text
0 - 29    NORMAL
30 - 59   SUSPICIOUS
60 - 100  HIGH RISK
```

I valori sono iniziali e dovranno essere calibrati durante i test.

Il sistema deve mostrare anche **perché** è stato assegnato un determinato punteggio.

Esempio:

```text
RISK SCORE: 78/100

Reasons:
- Work Weight: 91%
- 340 unique destination IPs
- 28 destination ports
- 145 connections/sec
- low SYN-ACK response ratio

STATUS: HIGH RISK
```

---

## 9. Finestra temporale

L'analisi deve essere effettuata su finestre temporali configurabili.

Default consigliato:

```text
WINDOW_SIZE = 30 seconds
```

La scelta è coerente con il paper, che raccoglie i tuple durante periodi di campionamento di trenta secondi.

Il sistema dovrebbe consentire di modificare la durata, ad esempio:

```text
10 s
30 s
60 s
300 s
```

---

## 10. Output console

La prima versione deve funzionare senza interfaccia grafica.

Esempio:

```text
==================================================
HOST NETWORK MONITOR
==================================================

Window: 10:30:00 - 10:30:30

TCP packets:          1842
SYN sent:              731
SYN-ACK received:      12
FIN sent:               31
RST received:          684

Unique destination IP: 421
Unique destination port: 17

TCP Work Weight:      78.7%
Risk Score:            82/100

STATUS: HIGH RISK
--------------------------------------------------
Reasons:
[!] High Work Weight
[!] Large number of destinations
[!] High SYN/SYN-ACK imbalance
==================================================
```

---

## 11. Dashboard opzionale

Come estensione, realizzare una dashboard web locale.

Possibili tecnologie:

- Flask;
- FastAPI + frontend semplice;
- Streamlit.

La dashboard può mostrare:

- Work Weight nel tempo;
- Risk Score nel tempo;
- numero di SYN;
- numero di RST;
- destinazioni contattate;
- porte contattate;
- eventi sospetti.

Esempio:

```text
+------------------------------------------------+
|        HOST NETWORK ANOMALY DETECTOR           |
+------------------------------------------------+
| Work Weight       | Risk Score                 |
|      78.7%        |     82 / 100               |
+------------------------------------------------+
| SYN/sec           | Unique IP                  |
|      145          |       421                  |
+------------------------------------------------+
| STATUS: HIGH RISK                              |
+------------------------------------------------+
```

---

## 12. Struttura del progetto

Proposta:

```text
botnet-detector/
│
├── README.md
├── requirements.txt
│
├── src/
│   ├── main.py
│   ├── capture.py
│   ├── parser.py
│   ├── statistics.py
│   ├── work_weight.py
│   ├── risk_score.py
│   ├── detector.py
│   └── config.py
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

---

## 13. Requisiti tecnici

### Linguaggio

Python 3.x

### Librerie iniziali

```text
scapy
```

Per la dashboard, opzionalmente:

```text
flask
```

oppure:

```text
streamlit
```

### Sistema operativo

Il progetto può essere sviluppato su:

- Linux;
- Windows;
- macOS.

La cattura dei pacchetti può richiedere privilegi amministrativi/root e, a seconda del sistema operativo, un packet capture backend appropriato.

---

## 14. Modalità di test

Non è necessario utilizzare malware reale.

Creare un dataset di test controllato che rappresenti:

### Scenario A — traffico normale

```text
web browsing
DNS
HTTPS
download/upload
```

### Scenario B — molte connessioni

Generare traffico verso un insieme controllato di host/porte.

### Scenario C — simulazione di scanning

In un ambiente di laboratorio isolato, generare un comportamento che invii molti SYN verso destinazioni controllate.

L'obiettivo è verificare che:

```text
Normal traffic  -> basso Risk Score
Scanning-like   -> alto Risk Score
```

---

## 15. Sicurezza ed etica

Il programma deve essere progettato come strumento di **monitoraggio difensivo**.

I test di scanning devono essere eseguiti esclusivamente:

- sul proprio computer;
- su macchine proprie;
- in una rete/laboratorio autorizzato.

Non è necessario implementare funzioni per attaccare, infettare o compromettere sistemi.

---

## 16. Evoluzioni possibili

Dopo la prima versione è possibile aggiungere:

### A. Rilevamento del traffico cifrato

Non decrittare il traffico.

Analizzare invece metadati come:

```text
packet size
packet timing
connection duration
bytes sent/received
connection frequency
```

e verificare se il comportamento anomalo può essere rilevato anche senza conoscere il payload.

### B. Machine Learning

Utilizzare le statistiche raccolte come feature per un classificatore.

Esempio:

```text
Features
   |
   +-- Work Weight
   +-- SYN count
   +-- RST count
   +-- Unique IPs
   +-- Unique ports
   +-- Connections/sec
          |
          v
       Classifier
          |
      +---+---+
      |       |
    NORMAL  ANOMALY
```

Questa parte deve essere considerata un'estensione, non un requisito della prima versione.

---

## 17. Obiettivo finale del progetto

Il risultato finale deve essere un **Network Anomaly Detector host-based** capace di:

1. osservare il traffico del PC;
2. raccogliere statistiche TCP;
3. calcolare il TCP Work Weight;
4. individuare comportamenti compatibili con scanning;
5. combinare più indicatori in un Risk Score;
6. generare un alert comprensibile;
7. visualizzare l'evoluzione del comportamento nel tempo.

La caratteristica distintiva rispetto a una semplice implementazione del paper sarà l'estensione **host-based + behavioural analysis**, mantenendo il TCP Work Weight come metrica centrale.

---

## 18. Riferimento

Il progetto è basato sul documento fornito:

**Odai Marashdeh — "An Algorithm for Botnet Detection"**

Nel documento l'algoritmo combina analisi IRC e rilevamento di TCP SYN scanner; il Work Weight viene utilizzato come indicatore del comportamento dei singoli host. Il sistema originale correla poi tali informazioni tra gli host presenti nei canali IRC. 
