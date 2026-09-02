"""Calcolo del Risk Score e classificazione del comportamento."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional

from src.analysis.behavioural import compute_behavioural_indicators
from src.config import (
    MIN_PACKETS_FOR_DIVERSITY,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_SUSPICIOUS,
)

if TYPE_CHECKING:
    from src.analysis.statistics import StatisticsWindow

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
# diversità di porta aggregata sull'intera finestra che non è affidabile
# (vedi nota nel modulo behavioural).
SINGLE_TARGET_PORT_DIVERSITY_MAX_POINTS = 10

# Bonus TBF (specifiche sez. 4-5): intervalli quasi identici tra flow
# consecutivi verso la stessa destinazione, tipici di beaconing C&C
# periodico. Qui, a differenza degli altri bonus, è la CONCENTRAZIONE
# (bassa diversità) ad essere il segnale di anomalia.
BEACONING_MAX_POINTS = 10

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
HIGH_BEACONING_THRESHOLD = 0.8


def _is_diversity_reliable(stats):
    total_packets = stats.packets_sent + stats.packets_received
    return total_packets >= MIN_PACKETS_FOR_DIVERSITY


def _work_weight_value(indicators, stats, work_weight):
    return work_weight


def _work_weight_reason(indicators, stats, work_weight):
    if work_weight > HIGH_WORK_WEIGHT_THRESHOLD:
        return f"High Work Weight ({work_weight * 100:.0f}%)"
    return None


def _destination_ips_value(indicators, stats, work_weight):
    return min(indicators["unique_destination_ips"] / DESTINATION_IPS_SCALE, 1.0)


def _destination_ips_reason(indicators, stats, work_weight):
    if indicators["unique_destination_ips"] > LARGE_DESTINATION_IPS_THRESHOLD:
        return f"Large number of destination IPs ({indicators['unique_destination_ips']})"
    return None


def _destination_ports_value(indicators, stats, work_weight):
    return min(indicators["unique_destination_ports"] / DESTINATION_PORTS_SCALE, 1.0)


def _destination_ports_reason(indicators, stats, work_weight):
    if indicators["unique_destination_ports"] > LARGE_DESTINATION_PORTS_THRESHOLD:
        return f"Large number of destination ports ({indicators['unique_destination_ports']})"
    return None


def _connection_rate_value(indicators, stats, work_weight):
    return min(indicators["connections_per_second"] / CONNECTION_RATE_SCALE, 1.0)


def _connection_rate_reason(indicators, stats, work_weight):
    if indicators["connections_per_second"] > HIGH_CONNECTION_RATE_THRESHOLD:
        return f"High connection frequency ({indicators['connections_per_second']:.1f}/s)"
    return None


def _syn_ack_value(indicators, stats, work_weight):
    return 1.0 - indicators["syn_ack_ratio"]


def _syn_ack_reason(indicators, stats, work_weight):
    if stats.syn_sent > 0 and indicators["syn_ack_ratio"] < LOW_SYN_ACK_RATIO_THRESHOLD:
        return "Low SYN/SYN-ACK response ratio"
    return None


def _destination_ip_diversity_value(indicators, stats, work_weight):
    if not _is_diversity_reliable(stats):
        return 0.0
    return indicators["destination_ip_diversity"]


def _destination_ip_diversity_reason(indicators, stats, work_weight):
    if (
        _is_diversity_reliable(stats)
        and indicators["destination_ip_diversity"] > HIGH_DESTINATION_IP_DIVERSITY_THRESHOLD
    ):
        return (
            f"Evenly spread destination traffic, diversity index "
            f"{indicators['destination_ip_diversity']:.2f} (fan-out pattern)"
        )
    return None


# "single_target_port_diversity" e "beaconing_score" sono già filtrati a
# monte per affidabilità (MIN_PACKETS_PER_DESTINATION_FOR_DDP /
# MIN_FLOWS_PER_DESTINATION_FOR_TBF in src/analysis/behavioural.py, soglie
# in src/config.py): un default 0.0 può significare sia "dato
# insufficiente" sia "misurato e concentrato/disperso al minimo". È
# sicuro solo perché le soglie HIGH_*_THRESHOLD sotto sono tutte "> X":
# un nuovo indicatore con soglia "< X" dovrebbe gestire l'ambiguità
# esplicitamente invece di affidarsi a questo stesso default.
def _single_target_port_diversity_value(indicators, stats, work_weight):
    return indicators["single_target_port_diversity"]


def _single_target_port_diversity_reason(indicators, stats, work_weight):
    if indicators["single_target_port_diversity"] > HIGH_SINGLE_TARGET_PORT_DIVERSITY_THRESHOLD:
        return (
            f"Port sweep against a single destination, diversity index "
            f"{indicators['single_target_port_diversity']:.2f}"
        )
    return None


def _beaconing_value(indicators, stats, work_weight):
    return indicators["beaconing_score"]


def _beaconing_reason(indicators, stats, work_weight):
    if indicators["beaconing_score"] > HIGH_BEACONING_THRESHOLD:
        return (
            f"Periodic beaconing pattern detected, regularity index "
            f"{indicators['beaconing_score']:.2f}"
        )
    return None


@dataclass(frozen=True)
class ScoringRule:
    """Un indicatore: quanto pesa (`max_points`) e la sua logica custom
    (`value_fn` per lo score, `reason_fn` per l'eventuale motivazione
    testuale). Tenerle come funzioni nominate, non lambda inline, così
    ogni indicatore resta leggibile e testabile isolatamente."""

    max_points: float
    value_fn: Callable[[dict, "StatisticsWindow", float], float]
    reason_fn: Callable[[dict, "StatisticsWindow", float], Optional[str]]


# Stesso ordine dei blocchi della versione precedente di compute_risk_score,
# per non spiazzare chi confronta il diff.
SCORING_RULES = [
    ScoringRule(WORK_WEIGHT_MAX_POINTS, _work_weight_value, _work_weight_reason),
    ScoringRule(DESTINATION_IPS_MAX_POINTS, _destination_ips_value, _destination_ips_reason),
    ScoringRule(DESTINATION_PORTS_MAX_POINTS, _destination_ports_value, _destination_ports_reason),
    ScoringRule(CONNECTION_RATE_MAX_POINTS, _connection_rate_value, _connection_rate_reason),
    ScoringRule(SYN_ACK_MAX_POINTS, _syn_ack_value, _syn_ack_reason),
    ScoringRule(
        DESTINATION_IP_DIVERSITY_MAX_POINTS,
        _destination_ip_diversity_value,
        _destination_ip_diversity_reason,
    ),
    ScoringRule(
        SINGLE_TARGET_PORT_DIVERSITY_MAX_POINTS,
        _single_target_port_diversity_value,
        _single_target_port_diversity_reason,
    ),
    ScoringRule(BEACONING_MAX_POINTS, _beaconing_value, _beaconing_reason),
]


def compute_risk_score(stats, work_weight):
    indicators = compute_behavioural_indicators(stats)

    score = 0.0
    reasons = []
    for rule in SCORING_RULES:
        score += rule.value_fn(indicators, stats, work_weight) * rule.max_points
        reason = rule.reason_fn(indicators, stats, work_weight)
        if reason:
            reasons.append(reason)

    score = round(min(score, 100))

    if score >= RISK_THRESHOLD_HIGH:
        status = "HIGH RISK"
    elif score >= RISK_THRESHOLD_SUSPICIOUS:
        status = "SUSPICIOUS"
    else:
        status = "NORMAL"

    return {"score": score, "status": status, "reasons": reasons, "indicators": indicators}
