from collections import Counter

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, rdpcap, sniff
from scapy.packet import Packet

from tp1.utils.config import logger
from tp1.utils.detectors import (
    Attack,
    detect_arp_spoofing,
    detect_port_scan,
    detect_sql_injection,
    find_flag,
)
from tp1.utils.lib import choose_interface

# Quels détecteurs lancer pour chaque protocole
DETECTORS = {
    "arp": [detect_arp_spoofing],
    "tcp": [detect_port_scan, detect_sql_injection],
}


def get_protocol(pkt: Packet) -> str:
    """
    Return the protocol name of a packet (ARP, DNS, TCP, UDP, ICMP, IPv6, IP or Other)
    """
    for layer, name in ((ARP, "ARP"), (DNS, "DNS"), (TCP, "TCP"), (UDP, "UDP"), (ICMP, "ICMP")):
        if pkt.haslayer(layer):
            return name
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IP"
    return "Other"


class Capture:
    def __init__(self, interface: str | None = None, pcap_path: str | None = None) -> None:
        self.pcap_path = pcap_path
        # Avec un fichier pcap, pas besoin de choisir une interface
        self.interface = interface or ("" if pcap_path else choose_interface())
        self.summary = ""
        self.packets = []
        self.attacks: list[Attack] = []
        self.flag = ""

    def capture_traffic(self, count: int = 0, timeout: int | None = 30) -> None:
        """
        Capture network traffic from an interface (or read it from a pcap file)
        """
        if self.pcap_path:
            logger.info(f"Lecture du fichier {self.pcap_path}")
            self.packets = list(rdpcap(self.pcap_path))
        else:
            logger.info(f"Capture sur l'interface {self.interface} (timeout={timeout}s, count={count})")
            self.packets = list(sniff(iface=self.interface or None, count=count, timeout=timeout, store=True))
        logger.info(f"{len(self.packets)} paquet(s) récupéré(s)")

    def sort_network_protocols(self) -> dict[str, list]:
        """
        Sort and return all captured network protocols (protocol -> packets)
        """
        sorted_packets = {}
        for pkt in self.packets:
            sorted_packets.setdefault(get_protocol(pkt), []).append(pkt)
        return sorted_packets

    def get_all_protocols(self) -> dict[str, int]:
        """
        Return all protocols captured with total packets number
        """
        counter = Counter(get_protocol(pkt) for pkt in self.packets)
        return dict(counter.most_common())

    def analyse(self, protocols: str = "all") -> None:
        """
        Analyse all captured data and return statement
        Si un trafic est illégitime (exemple : Injection SQL, ARP Spoofing, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine attaquante.
        Sinon afficher que tout va bien

        :param protocols: "all", ou une liste séparée par des virgules ("arp,tcp")
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.info(f"Protocoles trouvés : {all_protocols}")
        logger.debug(f"Protocoles triés : {list(sort)}")

        wanted = [name.strip().lower() for name in protocols.split(",")]
        self.attacks = []
        for name, detectors in DETECTORS.items():
            if "all" not in wanted and name not in wanted:
                logger.info(f"Analyse {name.upper()} ignorée")
                continue
            for detector in detectors:
                logger.info(f"Lancement de {detector.__name__}")
                self.attacks += detector(self.packets)

        for attack in self.attacks:
            logger.warning(
                f"ATTAQUE {attack.type} ({attack.protocol}) - attaquant {attack.attacker} "
                f"(MAC {attack.mac or '?'}, IP {attack.ip or '?'}) - {attack.detail}"
            )
        self.flag = find_flag(self.packets, self.attacks)
        if self.flag:
            logger.info(f"Flag trouvé : {self.flag}")
        if not self.attacks:
            logger.info("Aucune attaque détectée, tout va bien")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def is_protocol_legit(self, protocol: str) -> bool:
        """
        A protocol is legit if no attack was found on it
        """
        return all(attack.protocol != protocol for attack in self.attacks)

    def to_report_dict(self) -> dict:
        """
        Content of report.json (read by the automatic correction)
        """
        return {
            "protocols": self.get_all_protocols(),
            "attacks": [{"type": attack.type, "attacker": attack.attacker} for attack in self.attacks],
            "flag": self.flag,
        }

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        protocols = ", ".join(f"{name}: {number}" for name, number in self.get_all_protocols().items())
        summary = f"{len(self.packets)} paquets analysés ({protocols or 'aucun'}).\n"
        if not self.attacks:
            return summary + "Tout va bien : aucun trafic illégitime détecté."

        summary += f"{len(self.attacks)} tentative(s) d'attaque détectée(s) :\n"
        for attack in self.attacks:
            summary += (
                f"- {attack.type} ({attack.protocol}) : MAC {attack.mac}, IP {attack.ip or 'inconnue'}\n"
            )
        return summary
