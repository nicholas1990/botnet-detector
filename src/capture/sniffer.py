"""Cattura del traffico di rete tramite Scapy."""

from scapy.sendrecv import sniff


def start_capture(interface=None, packet_callback=None):
    """Avvia lo sniffing live dei pacchetti TCP.

    Richiede privilegi di root/amministratore per accedere all'interfaccia
    di rete. Ogni pacchetto TCP catturato viene passato a `packet_callback`.
    """
    sniff(iface=interface, filter="tcp", prn=packet_callback, store=False)
