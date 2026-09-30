"""Écrit un PCAP synthétique (trafic sain + ARP spoofing + scan SYN + injection SQL).

Fichier uniquement : rien n'est envoyé sur le réseau. Usage : python scripts/make_lab_pcap.py [sortie.pcap]
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import wrpcap

from tests.tp1.pcap_factory import full_scenario

if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
    packets = full_scenario()
    wrpcap(output, packets)
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("make_lab_pcap").info(f"{len(packets)} paquets écrits dans {output}")
