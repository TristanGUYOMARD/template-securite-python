import json
from datetime import datetime
from pathlib import Path

import pygal
from fpdf import FPDF

from tp1.utils.capture import Capture
from tp1.utils.config import logger

BAR_COLORS = [(31, 119, 180), (255, 127, 14), (44, 160, 44), (214, 39, 40), (148, 103, 189)]


def latin1(text: str) -> str:
    """Les polices de base du PDF ne connaissent que le latin-1, on remplace le reste par '?'."""
    return text.encode("latin-1", "replace").decode("latin-1")


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport d'analyse du trafic réseau (TP1 - IDS maison)"
        self.summary = summary
        self.array = []  # lignes du tableau : (protocole, paquets, part, statut)
        self.graph = []  # points du graphique : (protocole, paquets)

    def concat_report(self) -> str:
        """
        Concat all data in report (text version)
        """
        content = f"{self.title}\n\n{self.summary}\n"
        for protocol, packets, share, status in self.array:
            content += f"{protocol}\t{packets}\t{share}\t{status}\n"
        for label, value in self.graph:
            content += f"{label}: {value}\n"
        return content

    def save(self, filename: str) -> None:
        """
        Save report in a pdf file
        :param filename:
        :return:
        """
        logger.info(f"Écriture du PDF {filename}")
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        self._write_title(pdf)
        self._write_summary(pdf)
        self._write_array(pdf)
        self._write_graph(pdf)
        self._write_attacks(pdf)
        pdf.output(filename)

    def save_json(self, filename: str) -> None:
        """
        Save report.json (version lue par la correction automatique)
        """
        logger.info(f"Écriture du JSON {filename}")
        content = json.dumps(self.capture.to_report_dict(), indent=2, ensure_ascii=False)
        Path(filename).write_text(content, encoding="utf-8")

    def save_svg_chart(self, filename: str) -> None:
        """
        Save the same chart as a pygal svg (bonus)
        """
        logger.info(f"Écriture du graphique {filename}")
        chart = pygal.Bar(title="Paquets par protocole")
        for label, value in self.graph:
            chart.add(label, value)
        chart.render_to_file(filename)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        protocols = self.capture.get_all_protocols()
        total = sum(protocols.values()) or 1
        if param == "graph":
            logger.debug("Génération du graphique")
            self.graph = list(protocols.items())
        elif param == "array":
            logger.debug("Génération du tableau")
            self.array = []
            for protocol, packets in protocols.items():
                status = "Légitime" if self.capture.is_protocol_legit(protocol) else "ILLÉGITIME"
                self.array.append((protocol, packets, f"{100 * packets / total:.1f} %", status))
        else:
            logger.warning(f"Paramètre inconnu : {param}")

    def _write_title(self, pdf: FPDF) -> None:
        pdf.set_font("Helvetica", "B", 16)
        pdf.multi_cell(0, 9, latin1(self.title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        source = self.capture.pcap_path or f"interface {self.capture.interface}"
        date = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
        pdf.multi_cell(0, 5, latin1(f"Généré le {date} - source : {source}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

    def _write_section_title(self, pdf: FPDF, text: str) -> None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, latin1(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)

    def _write_summary(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Synthèse")
        pdf.multi_cell(0, 5.5, latin1(self.summary), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    def _write_array(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Protocoles reçus et légitimité du trafic")
        with pdf.table(col_widths=(35, 30, 30, 45), text_align="LEFT") as table:
            header = table.row()
            for name in ("Protocole", "Paquets", "Part", "Trafic"):
                header.cell(name)
            for protocol, packets, share, status in self.array:
                row = table.row()
                for value in (protocol, str(packets), share, status):
                    row.cell(latin1(value))
        pdf.ln(4)

    def _write_graph(self, pdf: FPDF) -> None:
        """Histogramme dessiné directement dans le PDF (un rectangle par protocole)."""
        height, width = 55, 170
        if pdf.get_y() + height + 25 > pdf.h - 15:
            pdf.add_page()
        self._write_section_title(pdf, "Graphique : paquets par protocole")
        if not self.graph:
            return

        left = pdf.l_margin + 5
        bottom = pdf.get_y() + height + 8
        biggest = max(value for _, value in self.graph) or 1
        slot = width / len(self.graph)
        for index, (label, value) in enumerate(self.graph):
            bar_height = height * value / biggest
            x = left + index * slot + slot * 0.15
            pdf.set_fill_color(*BAR_COLORS[index % len(BAR_COLORS)])
            pdf.rect(x, bottom - bar_height, slot * 0.7, bar_height, style="F")
            pdf.set_xy(x - 5, bottom - bar_height - 5)
            pdf.cell(slot * 0.7 + 10, 5, str(value), align="C")
            pdf.set_xy(x - 5, bottom + 1)
            pdf.cell(slot * 0.7 + 10, 5, latin1(label), align="C")
        pdf.line(left, bottom, left + width, bottom)
        pdf.set_y(bottom + 10)

    def _write_attacks(self, pdf: FPDF) -> None:
        self._write_section_title(pdf, "Tentatives d'attaque")
        if not self.capture.attacks:
            pdf.multi_cell(0, 6, "Tout va bien : aucun trafic illégitime détecté.")
            return

        for attack in self.capture.attacks:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, latin1(f"{attack.type} ({attack.protocol})"), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            lines = [
                f"Protocole : {attack.protocol}",
                f"Adresse physique (MAC) de l'attaquant : {attack.mac or 'inconnue'}",
                f"Adresse réseau (IP) de l'attaquant : {attack.ip or 'inconnue'}",
                f"Détail : {attack.detail}",
            ]
            for line in lines:
                pdf.multi_cell(0, 5, latin1(line), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        if self.capture.flag:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, latin1(f"Marqueur relevé : {self.capture.flag}"))
