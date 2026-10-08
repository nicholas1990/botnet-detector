"""Cattura del traffico di rete tramite Scapy."""

from scapy.sendrecv import sniff


def start_capture(interface=None, packet_callback=None, pcap_path=None):
    """Avvia lo sniffing live dei pacchetti TCP, o rilegge un file PCAP.

    In modalità live richiede privilegi di root/amministratore per accedere
    all'interfaccia di rete. Ogni pacchetto TCP catturato viene passato a
    `packet_callback`.

    Con `pcap_path` i pacchetti vengono letti dal file (nessun privilegio
    richiesto), utile per la validazione su dataset registrati. Il filtro BPF
    non viene applicato in questo caso perché Scapy lo delegherebbe a
    tcpdump, che potrebbe non essere installato: i pacchetti non TCP vengono
    comunque scartati da `parse_packet`.
    """
    if pcap_path is not None:
        sniff(offline=pcap_path, prn=packet_callback, store=False)
        return
    sniff(iface=interface, filter="tcp", prn=packet_callback, store=False)
