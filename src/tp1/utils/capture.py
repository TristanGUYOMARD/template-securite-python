from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, Packet, sniff

from tp1.utils.config import logger
from tp1.utils.detectors import Attaque, chercher_flag, verifier_arp, verifier_scan, verifier_sql
from tp1.utils.lib import choisir_interface

DETECTEURS = {
    "arp": [verifier_arp],
    "tcp": [verifier_scan, verifier_sql],
}


def trouver_protocole(paquet: Packet) -> str:
    """Donne le nom du protocole d'un paquet"""
    couches = [(ARP, "ARP"), (DNS, "DNS"), (TCP, "TCP"), (UDP, "UDP"), (ICMP, "ICMP")]
    for couche, nom in couches:
        if paquet.haslayer(couche):
            return nom
    if paquet.haslayer(IPv6):
        return "IPv6"
    if paquet.haslayer(IP):
        return "IP"
    return "Other"


def prendre_nombre(element: tuple[str, int]) -> int:
    """Donne le nombre de paquet d'un protocole"""
    return element[1]


class Capture:
    """Récupère les paquet et les analyse"""

    def __init__(self, interface: str | None = None, chemin_pcap: str | None = None) -> None:
        """Prépare la capture"""
        self.chemin_pcap = chemin_pcap
        if interface:
            self.interface = interface
        elif chemin_pcap:
            self.interface = ""
        else:
            self.interface = choisir_interface()
        self.resume = ""
        self.paquets: list[Packet] = []
        self.attaques: list[Attaque] = []
        self.flag = ""
        self.erreur = False

    def capturer(self, nombre: int = 0, delai: int | None = 30) -> None:
        """Récupère les paquets"""
        if self.chemin_pcap:
            logger.info(f"Lecture du fichier {self.chemin_pcap}")
            self.paquets = list(sniff(offline=self.chemin_pcap, store=True))
        else:
            logger.info(f"Capture sur l'interface {self.interface} (timeout={delai}s, count={nombre})")
            interface = self.interface or None
            self.paquets = list(sniff(iface=interface, count=nombre, timeout=delai, store=True))
        logger.info(f"{len(self.paquets)} paquet(s) récupéré(s)")

    def compter_protocoles(self) -> dict[str, int]:
        """Compte les paquets par protocole"""
        comptes: dict[str, int] = {}
        for paquet in self.paquets:
            nom = trouver_protocole(paquet)
            if nom in comptes:
                comptes[nom] += 1
            else:
                comptes[nom] = 1
        liste = sorted(comptes.items(), key=prendre_nombre, reverse=True)
        return dict(liste)

    def lancer_detecteurs(self, protocoles: str) -> None:
        """Lance les détecteurs voulus (arp, tcp, etc...) et garde les attaques trouvées"""
        voulus = []
        for nom in protocoles.split(","):
            voulus.append(nom.strip().lower())

        self.attaques = []
        for nom in DETECTEURS:
            if "all" not in voulus and nom not in voulus:
                logger.info(f"Analyse {nom.upper()} ignorée")
                continue
            for detecteur in DETECTEURS[nom]:
                logger.info(f"Lancement de {detecteur.__name__}")
                self.attaques += detecteur(self.paquets)

    def afficher_attaques(self) -> None:
        """Écrit chaque attaque trouvée dans les log"""
        for attaque in self.attaques:
            logger.warning(
                f"ATTAQUE {attaque.type} ({attaque.protocole}) - attaquant {attaque.attaquant} "
                f"(MAC {attaque.mac or '?'}, IP {attaque.ip or '?'}) - {attaque.detail}"
            )

    def analyser(self, protocoles: str = "all") -> None:
        """Analyse les paquets : protocoles, attaques, flag et résumé"""
        comptes = self.compter_protocoles()
        logger.info(f"Protocoles trouvés : {comptes}")

        self.lancer_detecteurs(protocoles)
        self.afficher_attaques()

        self.flag = chercher_flag(self.paquets, self.attaques)
        if self.flag:
            logger.info(f"Flag trouvé : {self.flag}")
        if not self.attaques:
            logger.info("Aucune attaque détectée, tout va bien")

        self.resume = self.faire_resume()

    def est_legitime(self, protocole: str) -> bool:
        """Dit si aucune attaque n'a été trouvée sur ce protocole"""
        for attaque in self.attaques:
            if attaque.protocole == protocole:
                return False
        return True

    def donnees_json(self) -> dict:
        """Prépare le contenu de report.json """
        attaques = []
        for attaque in self.attaques:
            attaques.append({"type": attaque.type, "attacker": attaque.attaquant})
        return {
            "protocols": self.compter_protocoles(),
            "attacks": attaques,
            "flag": self.flag,
        }

    def faire_resume(self) -> str:
        """Ecrit le texte de résumé de l'analyse"""
        comptes = self.compter_protocoles()
        morceaux = []
        for nom in comptes:
            morceaux.append(f"{nom}: {comptes[nom]}")
        protocoles = ", ".join(morceaux)
        if protocoles == "":
            protocoles = "aucun"

        resume = f"{len(self.paquets)} paquets analysés ({protocoles}).\n"
        if not self.attaques:
            return resume + "Tout va bien : aucun trafic illégitime détecté."

        resume += f"{len(self.attaques)} tentative(s) d'attaque détectée(s) :\n"
        for attaque in self.attaques:
            ip = attaque.ip or "inconnu"
            resume += f"- {attaque.type} ({attaque.protocole}) : MAC {attaque.mac}, IP {ip}\n"
        return resume
