import argparse
from pathlib import Path

from scapy.error import Scapy_Exception

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def lire_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Lit les arguments de la ligne de commande"""
    parser = argparse.ArgumentParser(description="TP1 - IDS maison : capture et analyse du trafic réseau")
    parser.add_argument("--pcap", help="fichier pcap à analyser (sinon on écoute une interface)")
    parser.add_argument(
        "--out", default="report.json", help="fichier JSON de sortie (le PDF est écrit à côté)"
    )
    parser.add_argument("--iface", help="interface à écouter (sinon on la demande)")
    parser.add_argument(
        "-c", "--count", type=int, default=0, help="nombre de paquets à capturer (0 = pas de limite)"
    )
    parser.add_argument("-t", "--timeout", type=int, default=30, help="durée de la capture en secondes")
    return parser.parse_args(argv)


def lancer_capture(args: argparse.Namespace) -> Capture:
    """Capture le trafic et note s'il y a eu une erreur"""
    logger.info("Starting TP1")
    capture = Capture(interface=args.iface, chemin_pcap=args.pcap)
    try:
        capture.capturer(nombre=args.count, delai=args.timeout)
    except (OSError, Scapy_Exception) as erreur:
        logger.error(f"Impossible de récupérer le trafic : {erreur}")
        capture.erreur = True
    return capture


def lancer_analyse(capture: Capture) -> None:
    """Analyse le trafic capturé"""
    if capture.erreur:
        return
    capture.analyser()


def generer_rapport(capture: Capture, sortie: str) -> None:
    """Écrit le PDF, le JSON et le graphique SVG """
    if capture.erreur:
        return
    chemin_json = Path(sortie)
    chemin_json.parent.mkdir(parents=True, exist_ok=True)
    chemin_pdf = chemin_json.with_name("report.pdf")
    chemin_svg = chemin_json.with_name("protocols.svg")

    rapport = Report(capture, capture.resume)
    rapport.preparer_graphique()
    rapport.preparer_tableau()
    rapport.sauver_pdf(str(chemin_pdf))
    rapport.sauver_json(str(chemin_json))
    rapport.sauver_svg(str(chemin_svg))
    logger.info(f"Terminé, rapports écrits dans {chemin_json.parent}")


def code_retour(capture: Capture) -> int:
    """Donne le code de sortie du programme"""
    if capture.erreur:
        return 1
    return 0
