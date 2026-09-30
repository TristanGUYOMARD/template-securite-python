import argparse
import sys
from pathlib import Path

from scapy.error import Scapy_Exception

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logger.info("Starting TP1")

    capture = Capture(interface=args.iface, pcap_path=args.pcap)
    try:
        capture.capture_traffic(count=args.count, timeout=args.timeout)
    except (OSError, Scapy_Exception) as error:
        logger.error(f"Impossible de récupérer le trafic : {error}")
        return 1

    capture.analyse()
    summary = capture.get_summary()

    json_path = Path(args.out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    pdf_path = json_path.with_name("report.pdf")
    report = Report(capture, str(pdf_path), summary)
    report.generate("graph")
    report.generate("array")
    report.save(str(pdf_path))
    report.save_json(str(json_path))
    report.save_svg_chart(str(json_path.with_name("protocols.svg")))
    logger.info(f"Terminé, rapports écrits dans {json_path.parent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
