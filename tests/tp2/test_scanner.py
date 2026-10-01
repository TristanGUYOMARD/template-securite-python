from tp2.utils import scanner as module
from tp2.utils.scanner import YaraScanner


def test_regles_du_cours(chemin_regles):
    noms = YaraScanner(chemin_regles).scan(b"urlmon.dll URLDownloadToFileA")
    assert noms == ["Suspicious_Downloader"]


def test_regles_perso_du_meme_dossier(chemin_regles):
    # les règles personnelles (mes_regles.yar) sont chargées aussi
    noms = YaraScanner(chemin_regles).scan(b"ESGI{abc}")
    assert "Flag_ESGI" in noms


def test_pas_de_match(chemin_regles):
    assert YaraScanner(chemin_regles).scan(b"rien du tout") == []


def test_chemin_relatif_depuis_la_racine():
    # marche même si on lance depuis un autre dossier
    assert YaraScanner().scan(b"urlmon.dll URLDownloadToFileA") == ["Suspicious_Downloader"]


def test_fichier_absent(tmp_path):
    assert YaraScanner(str(tmp_path / "absent.yar")).scan(b"x") == []


def test_regle_invalide(tmp_path):
    (tmp_path / "bad.yar").write_text("rule { oups")
    assert YaraScanner(str(tmp_path / "bad.yar")).scan(b"x") == []


def test_chemin_avec_accents(tmp_path, chemin_regles):
    dossier = tmp_path / "é è"
    dossier.mkdir()
    (dossier / "r.yar").write_text('rule R { strings: $a = "abc" condition: $a }', encoding="utf-8")
    assert YaraScanner(str(dossier / "r.yar")).scan(b"xabcx") == ["R"]


def test_yara_absent(monkeypatch, chemin_regles):
    monkeypatch.setattr(module, "yara", None)
    assert YaraScanner(chemin_regles).scan(b"urlmon.dll URLDownloadToFileA") == []
