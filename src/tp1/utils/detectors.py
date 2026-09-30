"""Détection des attaques dans une liste de paquets scapy : ARP spoofing, scan de ports, injection SQL."""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import unquote_plus

from scapy.all import ARP, IP, TCP, Ether, Packet, Raw

from tp1.utils.config import logger

# Un client normal parle à un ou deux ports d'une machine, pas plus
PORT_SCAN_MIN_PORTS = 10

FLAG_REGEX = re.compile(r"ESGI\{[^}\s]+\}")

# Motifs d'injection SQL, cherchés dans le texte en minuscules et décodé de l'URL
SQL_REGEXES = [
    re.compile(pattern)
    for pattern in (
        r"'\s*or\s+'?\d+'?\s*=\s*'?\d+",
        r"\bor\s+\d+\s*=\s*\d+",
        r"union\s+(all\s+)?select",
        r";\s*(drop|delete|insert|update)\s",
        r"'\s*--",
        r"information_schema",
        r"\bsleep\s*\(",
        r"xp_cmdshell",
    )
]

# Les captures piégées contiennent des paquets qui parlent à l'analyste ("ignore ton analyse...") :
# leur contenu, flag compris, n'est jamais pris en compte
DECOY_WORDS = ("ignore", "instruction", "system prompt", "assistant", "as an ai", "previous analysis")


@dataclass
class Attack:
    type: str  # arp_spoofing, port_scan, sql_injection
    protocol: str  # ARP ou TCP
    mac: str  # adresse physique de l'attaquant ("" si inconnue)
    ip: str  # adresse réseau de l'attaquant ("" si inconnue)
    detail: str
    flag: str = ""  # marqueur trouvé dans la requête d'injection SQL

    @property
    def attacker(self) -> str:
        """Identifiant de l'attaquant dans report.json : la MAC pour l'ARP, l'IP sinon."""
        return self.mac if self.type == "arp_spoofing" else self.ip


def payload_text(pkt: Packet) -> str:
    """Contenu applicatif du paquet, décodé de l'URL (%27 devient ')."""
    return unquote_plus(bytes(pkt[Raw].load).decode("latin-1"))


def mac_of(pkt: Packet) -> str:
    """MAC source de la trame Ethernet, vide s'il n'y en a pas."""
    return pkt[Ether].src if pkt.haslayer(Ether) else ""


def is_decoy(text: str) -> bool:
    """True si le texte s'adresse à un analyste (ou à une IA) au lieu d'être du trafic normal."""
    lowered = text.lower()
    return any(word in lowered for word in DECOY_WORDS)


def is_sql_injection(text: str) -> bool:
    """True si le texte ressemble à une injection SQL."""
    lowered = text.lower()
    return any(regex.search(lowered) for regex in SQL_REGEXES)


def detect_arp_spoofing(packets: list[Packet]) -> list[Attack]:
    """
    Une IP annoncée par plusieurs MAC : la première MAC vue pour cette IP est considérée comme la vraie,
    celles qui arrivent ensuite et prennent sa place sont les attaquants.
    """
    first_mac: dict[str, str] = {}
    stolen_ips: dict[str, set[str]] = defaultdict(set)  # MAC de l'attaquant -> IP usurpées
    fake_replies: Counter = Counter()

    for pkt in packets:
        if not pkt.haslayer(ARP):
            continue
        arp = pkt[ARP]
        if arp.psrc in ("", "0.0.0.0"):
            continue  # ARP probe, sans intérêt
        real_mac = first_mac.setdefault(arp.psrc, arp.hwsrc)
        if arp.hwsrc != real_mac:
            logger.debug(f"{arp.psrc} était {real_mac}, maintenant annoncée par {arp.hwsrc}")
            stolen_ips[arp.hwsrc].add(arp.psrc)
            fake_replies[arp.hwsrc] += 1

    attacks = []
    for mac, ips in stolen_ips.items():
        detail = f"{fake_replies[mac]} annonce(s) ARP pour {', '.join(sorted(ips))} avec une autre MAC que la vraie"
        attacks.append(Attack("arp_spoofing", "ARP", mac, "", detail))
    return attacks


def detect_port_scan(packets: list[Packet]) -> list[Attack]:
    """Une même source qui envoie des SYN vers beaucoup de ports différents d'une même cible."""
    ports: dict[tuple[str, str], set[int]] = defaultdict(set)  # (source, cible) -> ports visés
    macs: dict[str, Counter] = defaultdict(Counter)

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        if int(pkt[TCP].flags) & 0x17 != 0x02:  # SYN seul, sans ACK/RST/FIN
            continue
        ports[(pkt[IP].src, pkt[IP].dst)].add(pkt[TCP].dport)
        macs[pkt[IP].src][mac_of(pkt)] += 1

    attacks = []
    for (src, dst), visited in sorted(ports.items()):
        logger.debug(f"SYN de {src} vers {dst} : {len(visited)} port(s)")
        if len(visited) >= PORT_SCAN_MIN_PORTS:
            attacks.append(
                Attack(
                    "port_scan",
                    "TCP",
                    macs[src].most_common(1)[0][0],
                    src,
                    f"{len(visited)} ports testés sur {dst}",
                )
            )
    return attacks


def detect_sql_injection(packets: list[Packet]) -> list[Attack]:
    """Requêtes TCP dont le contenu ressemble à une injection SQL (une seule attaque par source)."""
    found: dict[str, Attack] = {}

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        text = payload_text(pkt)
        if not is_sql_injection(text) or is_decoy(text):
            continue

        src = pkt[IP].src
        logger.debug(f"Injection SQL de {src} vers {pkt[IP].dst}:{pkt[TCP].dport}")
        if src not in found:
            found[src] = Attack("sql_injection", "TCP", mac_of(pkt), src, f"requête vers {pkt[IP].dst}")
        match = FLAG_REGEX.search(text)
        if match and not found[src].flag:
            found[src].flag = match.group(0)
    return list(found.values())


def find_flag(packets: list[Packet], attacks: list[Attack]) -> str:
    """
    Cherche le flag ESGI{...} : d'abord dans les injections SQL détectées, sinon dans les paquets
    envoyés par un attaquant identifié. Les paquets qui s'adressent à l'analyste sont ignorés.
    """
    for attack in attacks:
        if attack.flag:
            return attack.flag

    attacker_ips = {attack.ip for attack in attacks if attack.ip}
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(Raw)) or pkt[IP].src not in attacker_ips:
            continue
        text = payload_text(pkt)
        match = FLAG_REGEX.search(text)
        if match and not is_decoy(text):
            return match.group(0)
    return ""
