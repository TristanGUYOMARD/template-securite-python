import os
import sys

from scapy.all import conf, get_if_list

from tp1.utils.config import logger


def lister_interfaces() -> list[str]:
    """Liste les interfaces réseau connues par scapy"""
    try:
        noms = get_if_list()
    except (OSError, ValueError) as erreur:
        logger.error(f"Impossible de lister les interfaces : {erreur}")
        return []
    interfaces = []
    for nom in noms:
        interfaces.append(str(nom))
    return interfaces


def interface_par_defaut(interfaces: list[str]) -> str:
    """Donne l'interface principale, ou la première de la liste"""
    if conf.iface:
        return str(conf.iface)
    if interfaces:
        return interfaces[0]
    return ""


def choisir_interface() -> str:
    """permet de choisir l'interface"""
    depuis_env = os.environ.get("TP1_INTERFACE", "").strip()
    if depuis_env:
        logger.info(f"Interface donnée par TP1_INTERFACE : {depuis_env}")
        return depuis_env

    interfaces = lister_interfaces()
    defaut = interface_par_defaut(interfaces)
    logger.debug(f"Interfaces trouvées : {interfaces}")
    if not interfaces or not sys.stdin.isatty():
        logger.info(f"Interface par défaut : {defaut}")
        return defaut

    numero = 0
    for nom in interfaces:
        logger.info(f"[{numero}] {nom}")
        numero += 1
    reponse = input(f"Numéro de l'interface à écouter (entrée = {defaut}) : ").strip()
    if reponse.isdigit() and int(reponse) < len(interfaces):
        return interfaces[int(reponse)]
    logger.info(f"Choix vide ou invalide, on prend {defaut}")
    return defaut
