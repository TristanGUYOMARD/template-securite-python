"""Écrit un PCAP synthétique (trafic sain + ARP spoofing + scan SYN + injection SQL).

Fichier uniquement : rien n'est envoyé sur le réseau. Usage : python scripts/make_lab_pcap.py [sortie.pcap]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import wrpcap  # noqa: E402

from tests.tp1.pcap_factory import full_scenario  # noqa: E402

if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
    packets = full_scenario()
    wrpcap(output, packets)
    print(f"{len(packets)} paquets écrits dans {output}")
