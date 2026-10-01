"""Rapports du triage : PDF (fpdf2) et JSON."""

import json

from fpdf import FPDF

from tp2.utils.config import logger


def en_latin1(texte: str) -> str:
    """Remplace les caractères que la police du PDF ne sait pas écrire."""
    return str(texte).encode("latin-1", "replace").decode("latin-1")


class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        r = self.result
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Rapport de triage de malware", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
        self.ligne(pdf, "SHA-256", r.get("sha256", ""))
        self.ligne(pdf, "MD5", r.get("md5", ""))
        self.ligne(pdf, "Taille", f"{r.get('size', 0)} octets")
        self.ligne(pdf, "Type", r.get("file_type", ""))
        self.ligne(pdf, "Entropie", r.get("entropy", 0))
        self.ligne(pdf, "Score", f"{r.get('score', 0)} / 10")
        self.ligne(pdf, "Famille probable", r.get("family_guess", ""))
        self.ligne(pdf, "Flag", r.get("flag") or "aucun")
        self.titre(pdf, "Règles YARA")
        self.liste(pdf, r.get("yara_matches", []))
        self.titre(pdf, "Techniques MITRE ATT&CK")
        self.liste(pdf, r.get("mitre_attack", []))
        for nom, valeurs in r.get("iocs", {}).items():
            self.titre(pdf, f"IOC : {nom}")
            self.liste(pdf, valeurs)
        self.titre(pdf, "Imports")
        self.liste(pdf, r.get("imports", [])[:50])
        self.titre(pdf, "Résumé")
        pdf.multi_cell(0, 6, en_latin1(r.get("llm_summary", "")), new_x="LMARGIN", new_y="NEXT")
        pdf.output(out_pdf)
        logger.info(f"Rapport PDF écrit : {out_pdf}")

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        with open(out_json, "w", encoding="utf-8") as fichier:
            json.dump(self.result, fichier, indent=2, ensure_ascii=False)
        logger.info(f"Rapport JSON écrit : {out_json}")

    def titre(self, pdf: FPDF, texte: str) -> None:
        """Écrit un titre de section."""
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, en_latin1(texte), new_x="LMARGIN", new_y="NEXT")

    def ligne(self, pdf: FPDF, nom: str, valeur) -> None:
        """Écrit une ligne 'nom : valeur'."""
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(40, 6, en_latin1(nom))
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, en_latin1(valeur), new_x="LMARGIN", new_y="NEXT")

    def liste(self, pdf: FPDF, valeurs: list) -> None:
        """Écrit une valeur par ligne ('aucun' si la liste est vide)."""
        pdf.set_font("Helvetica", "", 10)
        for valeur in valeurs or ["aucun"]:
            pdf.multi_cell(0, 5, en_latin1(f"- {valeur}"), new_x="LMARGIN", new_y="NEXT")
