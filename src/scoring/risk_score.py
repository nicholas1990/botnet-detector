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
# Assegnato solo se le connessioni falliscono (rapporto SYN/SYN-ACK basso):
# da sola la diversità non distingue il browsing verso molte CDN (mediana
# 0.79 su CTU-Normal-20) da un bot (0.82 su Neris) ed era la prima causa di
# falsi positivi (vedi docs/valutazione_dataset.md).
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

# Beaconing a lungo periodo osservato tra finestre (src/analysis/history.py):
# basta da solo a rendere la finestra SUSPICIOUS, perché un bot silenzioso
# non accumula punti dagli altri indicatori. Con 10 o 20 punti lo split di
# taratura non guadagnava quasi nulla (vedi docs/valutazione_dataset.md).
LONG_PERIOD_BEACONING_MAX_POINTS = 30

# Scale di normalizzazione: valore oltre il quale l'indicatore
# contribuisce con il massimo dei punti.
DESTINATION_IPS_SCALE = 50
# Fan-out con connessioni riuscite: il browsing normale arriva a decine di
# IP per finestra (p99 83 su CTU-Normal-20, più di Neris), quindi i punti
# partono solo oltre DESTINATION_IPS_SCALE e arrivano al massimo a
# SUCCESSFUL_FAN_OUT_IPS_SCALE (vedi docs/valutazione_dataset.md).
SUCCESSFUL_FAN_OUT_IPS_SCALE = 150
DESTINATION_PORTS_SCALE = 15
CONNECTION_RATE_SCALE = 5.0

# Soglie per generare le motivazioni testuali del punteggio.
HIGH_WORK_WEIGHT_THRESHOLD = 0.5
LARGE_DESTINATION_IPS_THRESHOLD = 50
# Con connessioni riuscite il reason compare solo quando la regola assegna
# almeno metà dei suoi punti, per non segnalare come anomalo un fan-out che
# lo score considera normale.
LARGE_SUCCESSFUL_FAN_OUT_IPS_THRESHOLD = 100
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


def _connections_mostly_fail(indicators, stats):
    return stats.syn_sent > 0 and indicators["syn_ack_ratio"] < LOW_SYN_ACK_RATIO_THRESHOLD


def _destination_ips_value(indicators, stats, work_weight):
    """Molte destinazioni pesano subito se le connessioni falliscono (scan,
    spam); se riescono contano solo i fan-out ben oltre il browsing normale."""
    destinations = indicators["unique_destination_ips"]
    if _connections_mostly_fail(indicators, stats):
        return min(destinations / DESTINATION_IPS_SCALE, 1.0)
    excess = max(destinations - DESTINATION_IPS_SCALE, 0)
    return min(excess / (SUCCESSFUL_FAN_OUT_IPS_SCALE - DESTINATION_IPS_SCALE), 1.0)


def _destination_ips_reason(indicators, stats, work_weight):
    threshold = (
        LARGE_DESTINATION_IPS_THRESHOLD
        if _connections_mostly_fail(indicators, stats)
        else LARGE_SUCCESSFUL_FAN_OUT_IPS_THRESHOLD
    )
    if indicators["unique_destination_ips"] > threshold:
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
    if _connections_mostly_fail(indicators, stats):
        return "Low SYN/SYN-ACK response ratio"
    return None


def _is_failing_fan_out(indicators, stats):
    """Fan-out da considerare: campione sufficiente e connessioni per lo più
    senza risposta (scan, spam). Fan-out con connessioni riuscite è il
    normale browsing su più host."""
    return _is_diversity_reliable(stats) and _connections_mostly_fail(indicators, stats)


def _destination_ip_diversity_value(indicators, stats, work_weight):
    if not _is_failing_fan_out(indicators, stats):
        return 0.0
    return indicators["destination_ip_diversity"]


def _destination_ip_diversity_reason(indicators, stats, work_weight):
    if (
        _is_failing_fan_out(indicators, stats)
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


def _long_period_beaconing_value(indicators, stats, work_weight):
    return 1.0 if indicators["periodic_destinations"] else 0.0


def _long_period_beaconing_reason(indicators, stats, work_weight):
    destinations = indicators["periodic_destinations"]
    if not destinations:
        return None
    ip, port = destinations[0]
    others = f" and {len(destinations) - 1} more" if len(destinations) > 1 else ""
    return f"Long-period beaconing across windows to {ip}:{port}{others}"


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
    ScoringRule(
        LONG_PERIOD_BEACONING_MAX_POINTS,
        _long_period_beaconing_value,
        _long_period_beaconing_reason,
    ),
]


def compute_risk_score(stats, work_weight, periodic_destinations=()):
    """`periodic_destinations`: coppie (IP, porta) segnalate dalla memoria tra
    finestre del Detector; vuoto quando si valuta una finestra isolata."""
    indicators = compute_behavioural_indicators(stats)
    indicators["periodic_destinations"] = list(periodic_destinations)

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
