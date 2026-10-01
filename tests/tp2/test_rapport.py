import json

from tp2.utils.report import Report, en_latin1

RESULTAT = {
    "sha256": "ab" * 32,
    "md5": "cd" * 16,
    "size": 10,
    "file_type": "PE",
    "entropy": 5.5,
    "score": 7,
    "family_guess": "Test",
    "flag": "ESGI{x}",
    "yara_matches": ["R1"],
    "mitre_attack": ["T1105"],
    "iocs": {"urls": ["http://evil.test/" + "a" * 200], "ips": []},
    "imports": ["VirtualAlloc"],
    "llm_summary": "Résumé accentué → et symbole",
}


def test_json(tmp_path):
    sortie = tmp_path / "r.json"
    Report(RESULTAT).generate_json(str(sortie))
    assert json.loads(sortie.read_text(encoding="utf-8")) == RESULTAT


def test_pdf(tmp_path):
    sortie = tmp_path / "r.pdf"
    Report(RESULTAT).generate_pdf(str(sortie))
    assert sortie.read_bytes().startswith(b"%PDF")


def test_pdf_resultat_vide(tmp_path):
    sortie = tmp_path / "v.pdf"
    Report({}).generate_pdf(str(sortie))
    assert sortie.stat().st_size > 0


def test_latin1():
    assert en_latin1("é→") == "é?"
