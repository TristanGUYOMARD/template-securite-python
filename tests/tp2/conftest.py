"""Fichiers fictifs (jamais de vrai malware) pour les tests du TP2."""

from pathlib import Path

import pytest

REGLES = Path(__file__).resolve().parents[2] / "rules" / "course_rules.yar"

FAUX = (
    b"MZ\x90\x00 fake sample\n"
    b"http://evil-c2.test/payload.bin ip 8.8.4.4 host bad-domain.org\n"
    b"Global\\MonMutexFake HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x\n"
    b"urlmon.dll URLDownloadToFileA ESGI{flag_de_test}\n" + "domaine-wide.net".encode("utf-16-le")
)


@pytest.fixture
def chemin_faux(tmp_path) -> str:
    """Écrit un faux fichier dans un dossier temporaire."""
    fichier = tmp_path / "faux.bin"
    fichier.write_bytes(FAUX)
    return str(fichier)


@pytest.fixture
def chemin_regles() -> str:
    """Chemin des règles YARA du projet."""
    return str(REGLES)
