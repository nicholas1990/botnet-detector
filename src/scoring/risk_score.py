"""Calcolo del Risk Score e classificazione del comportamento."""

from src.analysis.behavioural import compute_behavioural_indicators
from src.config import RISK_THRESHOLD_HIGH, RISK_THRESHOLD_SUSPICIOUS

# Punti massimi assegnabili per ciascun indicatore. Il totale supera 100:
# il punteggio finale viene comunque troncato a 100 (vedi sotto).
# Valori iniziali, da calibrare durante i test (vedi specifiche, sez. 8).
WORK_WEIGHT_MAX_POINTS = 40
DESTINATION_IPS_MAX_POINTS = 25
DESTINATION_PORTS_MAX_POINTS = 15
CONNECTION_RATE_MAX_POINTS = 10
SYN_ACK_MAX_POINTS = 10

# Bonus basato sul Simpson Diversity Index (specifiche sez. 5): rinforza il
# segnale "molte destinazioni" quando sono anche colpite in modo uniforme
# (fan-out tipico di scan/botnet), invece di limitarsi al conteggio grezzo.
DESTINATION_IP_DIVERSITY_MAX_POINTS = 10

# Bonus DDP per-coppia (specifiche sez. 4/6): una singola destinazione
# sondata su molte porte diverse (port sweep verticale), a differenza della
# diversita' di porta aggregata sull'intera finestra che non e' affidabile
# (vedi nota nel modulo behavioural).
SINGLE_TARGET_PORT_DIVERSITY_MAX_POINTS = 10

# Sotto questa soglia di pacchetti totali l'indice di diversita' non e'
# affidabile (poche osservazioni, vedi specifiche sez. 3) e viene ignorato
# nello scoring, pur restando calcolato e visibile negli indicatori.
MIN_PACKETS_FOR_DIVERSITY = 5

# Scale di normalizzazione: valore oltre il quale l'indicatore
# contribuisce con il massimo dei punti.
DESTINATION_IPS_SCALE = 50
DESTINATION_PORTS_SCALE = 15
CONNECTION_RATE_SCALE = 5.0

# Soglie per generare le motivazioni testuali del punteggio.
HIGH_WORK_WEIGHT_THRESHOLD = 0.5
LARGE_DESTINATION_IPS_THRESHOLD = 50
LARGE_DESTINATION_PORTS_THRESHOLD = 15
HIGH_CONNECTION_RATE_THRESHOLD = 5.0
LOW_SYN_ACK_RATIO_THRESHOLD = 0.3
HIGH_DESTINATION_IP_DIVERSITY_THRESHOLD = 0.8
HIGH_SINGLE_TARGET_PORT_DIVERSITY_THRESHOLD = 0.8


def compute_risk_score(stats, work_weight):
    indicators = compute_behavioural_indicators(stats)

    score = work_weight * WORK_WEIGHT_MAX_POINTS
    score += (
        min(indicators["unique_destination_ips"] / DESTINATION_IPS_SCALE, 1.0)
        * DESTINATION_IPS_MAX_POINTS
    )
    score += (
        min(indicators["unique_destination_ports"] / DESTINATION_PORTS_SCALE, 1.0)
        * DESTINATION_PORTS_MAX_POINTS
    )
    score += (
        min(indicators["connections_per_second"] / CONNECTION_RATE_SCALE, 1.0)
        * CONNECTION_RATE_MAX_POINTS
    )
    score += (1.0 - indicators["syn_ack_ratio"]) * SYN_ACK_MAX_POINTS

    total_packets = stats.packets_sent + stats.packets_received
    diversity_reliable = total_packets >= MIN_PACKETS_FOR_DIVERSITY
    if diversity_reliable:
        score += indicators["destination_ip_diversity"] * DESTINATION_IP_DIVERSITY_MAX_POINTS
    score += indicators["single_target_port_diversity"] * SINGLE_TARGET_PORT_DIVERSITY_MAX_POINTS

    score = round(min(score, 100))

    reasons = []
    if work_weight > HIGH_WORK_WEIGHT_THRESHOLD:
        reasons.append(f"High Work Weight ({work_weight * 100:.0f}%)")
    if indicators["unique_destination_ips"] > LARGE_DESTINATION_IPS_THRESHOLD:
        reasons.append(
            f"Large number of destination IPs ({indicators['unique_destination_ips']})"
        )
    if indicators["unique_destination_ports"] > LARGE_DESTINATION_PORTS_THRESHOLD:
        reasons.append(
            f"Large number of destination ports ({indicators['unique_destination_ports']})"
        )
    if indicators["connections_per_second"] > HIGH_CONNECTION_RATE_THRESHOLD:
        reasons.append(
            f"High connection frequency ({indicators['connections_per_second']:.1f}/s)"
        )
    if stats.syn_sent > 0 and indicators["syn_ack_ratio"] < LOW_SYN_ACK_RATIO_THRESHOLD:
        reasons.append("Low SYN/SYN-ACK response ratio")
    if (
        diversity_reliable
        and indicators["destination_ip_diversity"] > HIGH_DESTINATION_IP_DIVERSITY_THRESHOLD
    ):
        reasons.append(
            f"Evenly spread destination traffic, diversity index "
            f"{indicators['destination_ip_diversity']:.2f} (fan-out pattern)"
        )
    if indicators["single_target_port_diversity"] > HIGH_SINGLE_TARGET_PORT_DIVERSITY_THRESHOLD:
        reasons.append(
            f"Port sweep against a single destination, diversity index "
            f"{indicators['single_target_port_diversity']:.2f}"
        )

    if score >= RISK_THRESHOLD_HIGH:
        status = "HIGH RISK"
    elif score >= RISK_THRESHOLD_SUSPICIOUS:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    return {"score": score, "status": status, "reasons": reasons}
