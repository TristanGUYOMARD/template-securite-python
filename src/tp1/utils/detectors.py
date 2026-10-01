import re
from urllib.parse import unquote_plus

from scapy.all import ARP, IP, TCP, Ether, Packet, Raw

from tp1.utils.config import logger

MIN_PORTS = 10
MASQUE_SYN = 0x17
SYN_SEUL = 0x02

MOTIF_FLAG = re.compile(r"ESGI\{[^}\s]+\}")

TEXTES_SQL = [
    r"'\s*or\s+'?\d+'?\s*=\s*'?\d+",
    r"\bor\s+\d+\s*=\s*\d+",
    r"union\s+(all\s+)?select",
    r";\s*(drop|delete|insert|update)\s",
    r"'\s*--",
    r"information_schema",
    r"\bsleep\s*\(",
    r"xp_cmdshell",
]
MOTIFS_SQL = []
for texte in TEXTES_SQL:
    MOTIFS_SQL.append(re.compile(texte))

MOTS_LEURRE = ["ignore", "instruction", "system prompt", "assistant", "as an ai", "previous analysis"]


class Attaque:
    """si une attaque est détecté dans le trafic"""

    def __init__(self, type: str, protocole: str, mac: str, ip: str, detail: str, flag: str = "") -> None:
        """Garde les informations de l'attaque."""
        self.type = type
        self.protocole = protocole
        self.mac = mac
        self.ip = ip
        self.detail = detail
        self.flag = flag

        if type == "arp_spoofing":
            self.attaquant = mac
        else:
            self.attaquant = ip


def lire_texte(paquet: Packet) -> str:
    """Lit le contenu du paquet et les décode"""
    contenu = bytes(paquet[Raw].load)
    texte = contenu.decode("latin-1")
    return unquote_plus(texte)


def lire_mac(paquet: Packet) -> str:
    """Donne la MAC source de la trame Ethernet si elle existe"""
    if paquet.haslayer(Ether):
        return paquet[Ether].src

    return ""


def est_leurre(texte: str) -> bool:
    """ça signale si le texte s'adresse à un analyste au lieu d'être du trafic normal"""
    texte_minuscule = texte.lower()

    for mot in MOTS_LEURRE:
        if mot in texte_minuscule:
            return True

    return False


def est_sql(texte: str) -> bool:
    """Dit si le texte ressemble à une injection SQL"""
    texte_minuscule = texte.lower()

    for motif in MOTIFS_SQL:
        if motif.search(texte_minuscule):
            return True

    return False


def mac_la_plus_frequente(comptes: dict[str, int]) -> str:
    """Trouve la MAC qui apparaît le plus souvent dans un dictionnaire de comptes"""
    meilleure_mac = ""
    meilleur_score = 0

    for mac in comptes:
        score = comptes[mac]
        if score > meilleur_score:
            meilleure_mac = mac
            meilleur_score = score

    return meilleure_mac


def verifier_arp(paquets: list[Packet]) -> list[Attaque]:
    """Cherche les IP annoncés par une autre MAC que la première MAC utilisé"""
    vraie_mac = {}
    ips_volees: dict[str, list[str]] = {}
    nombre_fausses = {}

    for paquet in paquets:
        if not paquet.haslayer(ARP):
            continue

        arp = paquet[ARP]
        if arp.psrc == "" or arp.psrc == "0.0.0.0":
            continue

        if arp.psrc not in vraie_mac:
            vraie_mac[arp.psrc] = arp.hwsrc

        if arp.hwsrc != vraie_mac[arp.psrc]:
            logger.debug(
                f"{arp.psrc} était {vraie_mac[arp.psrc]}, maintenant annoncée par {arp.hwsrc}"
            )

            if arp.hwsrc not in ips_volees:
                ips_volees[arp.hwsrc] = []
                nombre_fausses[arp.hwsrc] = 0

            if arp.psrc not in ips_volees[arp.hwsrc]:
                ips_volees[arp.hwsrc].append(arp.psrc)

            nombre_fausses[arp.hwsrc] += 1

    attaques = []
    for mac in ips_volees:
        liste_ips = ips_volees[mac]
        liste_ips.sort()
        ips = ", ".join(liste_ips)
        detail = f"{nombre_fausses[mac]} annonce(s) ARP pour {ips} avec une autre MAC que la vraie"
        attaque = Attaque("arp_spoofing", "ARP", mac, "", detail)
        attaques.append(attaque)

    return attaques


def verifier_scan(paquets: list[Packet]) -> list[Attaque]:
    """Cherche les source qui envoient des SYN vers beaucoup de ports d'une même cible"""
    ports: dict[tuple[str, str], list[int]] = {}
    macs: dict[str, dict[str, int]] = {}

    for paquet in paquets:
        if not paquet.haslayer(IP) or not paquet.haslayer(TCP):
            continue

        drapeaux = int(paquet[TCP].flags)
        if drapeaux & MASQUE_SYN != SYN_SEUL:
            continue

        source = paquet[IP].src
        cible = paquet[IP].dst
        cle = (source, cible)

        if cle not in ports:
            ports[cle] = []

        port_destination = paquet[TCP].dport
        if port_destination not in ports[cle]:
            ports[cle].append(port_destination)

        if source not in macs:
            macs[source] = {}

        mac = lire_mac(paquet)
        if mac not in macs[source]:
            macs[source][mac] = 0

        macs[source][mac] += 1

    attaques = []
    cles = list(ports.keys())
    cles.sort()

    for cle in cles:
        source, cible = cle
        nombre_ports = len(ports[cle])
        logger.debug(f"SYN de {source} vers {cible} : {nombre_ports} port(s)")

        if nombre_ports >= MIN_PORTS:
            mac = mac_la_plus_frequente(macs[source])
            detail = f"{nombre_ports} ports testés sur {cible}"
            attaque = Attaque("port_scan", "TCP", mac, source, detail)
            attaques.append(attaque)

    return attaques


def verifier_sql(paquets: list[Packet]) -> list[Attaque]:
    """Cherche les requêtes TCP qui ressemblent à une injection SQL"""
    attaques_par_source = {}

    for paquet in paquets:
        if not paquet.haslayer(IP) or not paquet.haslayer(TCP) or not paquet.haslayer(Raw):
            continue

        texte = lire_texte(paquet)
        if not est_sql(texte) or est_leurre(texte):
            continue

        source = paquet[IP].src
        cible = paquet[IP].dst
        port = paquet[TCP].dport
        logger.debug(f"Injection SQL de {source} vers {cible}:{port}")

        if source not in attaques_par_source:
            detail = f"requête vers {cible}"
            attaque = Attaque("sql_injection", "TCP", lire_mac(paquet), source, detail)
            attaques_par_source[source] = attaque

        resultat = MOTIF_FLAG.search(texte)
        if resultat and not attaques_par_source[source].flag:
            attaques_par_source[source].flag = resultat.group(0)

    return list(attaques_par_source.values())


def chercher_flag(paquets: list[Packet], attaques: list[Attaque]) -> str:
    """Cherche le flag dans les attaques, puis dans les paquets des attaquants"""
    for attaque in attaques:
        if attaque.flag:
            return attaque.flag

    ips_attaquants = []
    for attaque in attaques:
        if attaque.ip:
            ips_attaquants.append(attaque.ip)

    for paquet in paquets:
        if not paquet.haslayer(IP) or not paquet.haslayer(Raw):
            continue

        source = paquet[IP].src
        if source not in ips_attaquants:
            continue

        texte = lire_texte(paquet)
        resultat = MOTIF_FLAG.search(texte)
        if resultat and not est_leurre(texte):
            return resultat.group(0)

    return ""
