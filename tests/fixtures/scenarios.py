"""Dataset di traffico sintetico e controllato (specifiche sez. 14).

Scenario A: normale browsing (handshake completo + scambio dati, poche
destinazioni/porte).
Scenario B: molte connessioni legittime verso un insieme controllato di
host/porte (handshake completo, nessuna anomalia nel rapporto SYN/SYN-ACK).
Scenario C: simulazione di scanning (molti SYN verso molte destinazioni,
quasi nessuna risposta SYN-ACK, molti RST).
"""

from src.capture.parser import PacketRecord


def _connection(records, remote_ip, remote_port, t, data_packets=0):
    records.append(PacketRecord("sent", remote_ip, remote_port, "S", 60, t))
    records.append(PacketRecord("received", remote_ip, remote_port, "SA", 60, t + 0.01))
    t += 0.02
    for _ in range(data_packets):
        records.append(PacketRecord("sent", remote_ip, remote_port, "PA", 500, t))
        records.append(PacketRecord("received", remote_ip, remote_port, "PA", 1200, t + 0.01))
        t += 0.02
    records.append(PacketRecord("sent", remote_ip, remote_port, "FA", 60, t))
    records.append(PacketRecord("received", remote_ip, remote_port, "FA", 60, t + 0.01))
    return t + 0.02


def scenario_a_normal_traffic():
    """Web browsing / DNS / HTTPS: poche destinazioni, handshake completi."""
    destinations = [
        ("93.184.216.34", 443),
        ("142.250.72.14", 443),
        ("151.101.1.140", 443),
        ("8.8.8.8", 53),
        ("1.1.1.1", 53),
    ]
    records = []
    t = 0.0
    for remote_ip, remote_port in destinations:
        t = _connection(records, remote_ip, remote_port, t, data_packets=8)
    return records


def scenario_b_many_connections():
    """Molte connessioni legittime verso un insieme controllato di host/porte."""
    ports = [443, 80, 22, 21, 25, 110, 143, 993, 8080, 8443]
    records = []
    t = 0.0
    for i in range(40):
        remote_ip = f"198.51.100.{i + 1}"
        remote_port = ports[i % len(ports)]
        t = _connection(records, remote_ip, remote_port, t, data_packets=2)
    return records


def scenario_c_scanning():
    """SYN scan: molti SYN verso molte destinazioni, poche risposte SYN-ACK.

    `host_index` conta le connessioni in totale attraverso entrambe le porte,
    senza resettarsi tra un `port` e l'altro: solo le primissime iterazioni in
    assoluto (quelle sulla prima porta) ricevono SYN-ACK, tutto il resto —
    incluse tutte le connessioni sulla seconda porta — riceve RST. Va bene per
    lo scopo del test (simulare uno scan quasi-completamente respinto), ma
    non garantisce "N host aperti per porta"; se in futuro serve quel
    controllo più preciso, `host_index` va resettato a ogni iterazione di `port`.
    """
    ports = [445, 3389]
    records = []
    t = 0.0
    open_hosts = 3
    host_index = 0
    for port in ports:
        for i in range(50):
            remote_ip = f"203.0.113.{i + 1}"
            records.append(PacketRecord("sent", remote_ip, port, "S", 60, t))
            if host_index < open_hosts:
                records.append(
                    PacketRecord("received", remote_ip, port, "SA", 60, t + 0.01)
                )
            else:
                records.append(
                    PacketRecord("received", remote_ip, port, "RA", 60, t + 0.01)
                )
            host_index += 1
            t += 0.02
    return records
