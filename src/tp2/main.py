import argparse
import os

from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    ap.add_argument("--out", default=None, help="dossier des rapports (par défaut : à côté du fichier)")
    args = ap.parse_args()

    triage = Triage(args.file, args.llm)
    result = triage.run()

    # sans --out, les rapports sont écrits à côté du fichier analysé
    base = args.file
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        base = os.path.join(args.out, os.path.basename(args.file))

    report = Report(result)
    report.generate_pdf(f"{base}.triage.pdf")
    report.generate_json(f"{base}.triage.json")


if __name__ == "__main__":
    main()
