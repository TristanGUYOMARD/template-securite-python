import os
import sys

from scapy.all import conf, get_if_list

from tp1.utils.config import logger


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def list_interfaces() -> list[str]:
    """
    List the network interfaces known by scapy
    """
    try:
        return [str(name) for name in get_if_list()]
    except (OSError, ValueError) as error:
        logger.error(f"Impossible de lister les interfaces : {error}")
        return []


def default_interface(interfaces: list[str]) -> str:
    """
    Return the main interface (the one used by the default route), or the first one
    """
    if conf.iface:
        return str(conf.iface)
    return interfaces[0] if interfaces else ""


def choose_interface() -> str:
    """
    Return network interface and input user choice

    Order : variable TP1_INTERFACE, then the user's choice (if there is a terminal),
    then the main interface.

    :return: network interface
    """
    from_env = os.environ.get("TP1_INTERFACE", "").strip()
    if from_env:
        logger.info(f"Interface donnée par TP1_INTERFACE : {from_env}")
        return from_env

    interfaces = list_interfaces()
    default = default_interface(interfaces)
    logger.debug(f"Interfaces trouvées : {interfaces}")
    if not interfaces or not sys.stdin.isatty():
        logger.info(f"Interface par défaut : {default}")
        return default

    for number, name in enumerate(interfaces):
        logger.info(f"[{number}] {name}")
    answer = input(f"Numéro de l'interface à écouter (entrée = {default}) : ").strip()
    if answer.isdigit() and int(answer) < len(interfaces):
        return interfaces[int(answer)]
    logger.info(f"Choix vide ou invalide, on prend {default}")
    return default
