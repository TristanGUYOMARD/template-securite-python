import json
from datetime import datetime
from pathlib import Path

import pygal
from fpdf import FPDF

from tp1.utils.capture import Capture
from tp1.utils.config import logger

COULEURS = [(31, 119, 180), (255, 127, 14), (44, 160, 44), (214, 39, 40), (148, 103, 189)]


def en_latin1(texte: str) -> str:
    """Remplace les caractères que le PDF ne connaît pas"""
    return texte.encode("latin-1", "replace").decode("latin-1")


class Report:
    """Prépare et écrit les rapports PDF, JSON et SVG"""

    def __init__(self, capture: Capture, resume: str) -> None:
        """Garde la capture et le résumé du rapport."""
        self.capture = capture
        self.titre = "Rapport d'analyse du trafic réseau (TP1 - IDS maison)"
        self.resume = resume
        self.tableau: list[tuple[str, int, str, str]] = []
        self.graphique: list[tuple[str, int]] = []

    def preparer_graphique(self) -> None:
        """Prépare les points du graphique"""
        logger.debug("Génération du graphique")
        comptes = self.capture.compter_protocoles()
        self.graphique = list(comptes.items())

    def preparer_tableau(self) -> None:
        """Prépare les lignes du tableau"""
        logger.debug("Génération du tableau")
        comptes = self.capture.compter_protocoles()
        total = sum(comptes.values())
        if total == 0:
            total = 1
        self.tableau = []
        for protocole in comptes:
            nombre = comptes[protocole]
            if self.capture.est_legitime(protocole):
                statut = "Légitime"
            else:
                statut = "ILLÉGITIME"
            part = f"{100 * nombre / total:.1f} %"
            self.tableau.append((protocole, nombre, part, statut))

    def sauver_pdf(self, nom_fichier: str) -> None:
        """Écrit le rapport dans un fichier pdf"""
        logger.info(f"Écriture du PDF {nom_fichier}")
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        self.ecrire_titre(pdf)
        self.ecrire_resume(pdf)
        self.ecrire_tableau(pdf)
        self.ecrire_graphique(pdf)
        self.ecrire_attaques(pdf)
        pdf.output(nom_fichier)

    def sauver_json(self, nom_fichier: str) -> None:
        """Écrit report.json"""
        logger.info(f"Écriture du JSON {nom_fichier}")
        contenu = json.dumps(self.capture.donnees_json(), indent=2, ensure_ascii=False)
        Path(nom_fichier).write_text(contenu, encoding="utf-8")

    def sauver_svg(self, nom_fichier: str) -> None:
        """Écrit le graphique en fichier svg"""
        logger.info(f"Écriture du graphique {nom_fichier}")
        graphique = pygal.Bar(title="Paquets par protocole")
        for nom, valeur in self.graphique:
            graphique.add(nom, valeur)
        graphique.render_to_file(nom_fichier)

    def ecrire_titre(self, pdf: FPDF) -> None:
        """Écrit le titre et la source dans le pdf"""
        pdf.set_font("Helvetica", "B", 16)
        pdf.multi_cell(0, 9, en_latin1(self.titre), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        source = self.capture.chemin_pcap or f"interface {self.capture.interface}"
        date = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
        ligne = en_latin1(f"Généré le {date} - source : {source}")
        pdf.multi_cell(0, 5, ligne, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    def ecrire_section(self, pdf: FPDF, texte: str) -> None:
        """Écrit un titre de section dans le PDF."""
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, en_latin1(texte), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

    def ecrire_resume(self, pdf: FPDF) -> None:
        """Écrit la synthèse dans le pdf"""
        self.ecrire_section(pdf, "Synthèse")
        pdf.multi_cell(0, 5.5, en_latin1(self.resume), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    def ecrire_tableau(self, pdf: FPDF) -> None:
        """Écrit le tableau des protocole dans le pdf"""
        self.ecrire_section(pdf, "Protocoles reçus et légitimité du trafic")
        with pdf.table(col_widths=(35, 30, 30, 45), text_align="LEFT") as table:
            entete = table.row()
            for nom in ("Protocole", "Paquets", "Part", "Trafic"):
                entete.cell(nom)
            for protocole, nombre, part, statut in self.tableau:
                ligne = table.row()
                for valeur in (protocole, str(nombre), part, statut):
                    ligne.cell(en_latin1(valeur))
        pdf.ln(4)

    def ecrire_graphique(self, pdf: FPDF) -> None:
        """Dessine l'histogramme dans le pdf"""
        hauteur = 55
        largeur = 170
        if pdf.get_y() + hauteur + 25 > pdf.h - 15:
            pdf.add_page()
        self.ecrire_section(pdf, "Graphique : paquets par protocole")
        if not self.graphique:
            return

        gauche = pdf.l_margin + 5
        bas = pdf.get_y() + hauteur + 8
        maximum = 0
        for nom, valeur in self.graphique:
            if valeur > maximum:
                maximum = valeur
        if maximum == 0:
            maximum = 1
        case = largeur / len(self.graphique)

        numero = 0
        for nom, valeur in self.graphique:
            hauteur_barre = hauteur * valeur / maximum
            x = gauche + numero * case + case * 0.15
            pdf.set_fill_color(*COULEURS[numero % len(COULEURS)])
            pdf.rect(x, bas - hauteur_barre, case * 0.7, hauteur_barre, style="F")
            pdf.set_xy(x - 5, bas - hauteur_barre - 5)
            pdf.cell(case * 0.7 + 10, 5, str(valeur), align="C")
            pdf.set_xy(x - 5, bas + 1)
            pdf.cell(case * 0.7 + 10, 5, en_latin1(nom), align="C")
            numero += 1
        pdf.line(gauche, bas, gauche + largeur, bas)
        pdf.set_y(bas + 10)

    def ecrire_attaques(self, pdf: FPDF) -> None:
        """Écrit la liste des attaques dans le pdf"""
        self.ecrire_section(pdf, "Tentatives d'attaque")
        if not self.capture.attaques:
            pdf.multi_cell(0, 6, "Tout va bien : aucun trafic illégitime détecté.")
            return

        for attaque in self.capture.attaques:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, en_latin1(f"{attaque.type} ({attaque.protocole})"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            lignes = [
                f"Protocole : {attaque.protocole}",
                f"Adresse physique (MAC) de l'attaquant : {attaque.mac or 'inconnue'}",
                f"Adresse réseau (IP) de l'attaquant : {attaque.ip or 'inconnue'}",
                f"Détail : {attaque.detail}",
            ]
            for ligne in lignes:
                pdf.multi_cell(0, 5, en_latin1(ligne), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        if self.capture.flag:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, en_latin1(f"Marqueur relevé : {self.capture.flag}"))
