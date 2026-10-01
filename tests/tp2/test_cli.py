import json
import sys
from pathlib import Path

from tp2 import main as module
from tp2.utils.llm import LLMTriage


def test_main(tmp_path, chemin_faux, monkeypatch):
    monkeypatch.setattr(LLMTriage, "demander", lambda self, prompt: "pas du json")
    sortie = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", ["tp2", "-f", chemin_faux, "--llm", "ollama", "--out", str(sortie)])
    module.main()
    rapport = json.loads((sortie / "faux.bin.triage.json").read_text(encoding="utf-8"))
    assert rapport["flag"] == "ESGI{flag_de_test}"
    assert (sortie / "faux.bin.triage.pdf").read_bytes().startswith(b"%PDF")


def test_main_a_cote_du_fichier(chemin_faux, monkeypatch):
    monkeypatch.setattr(LLMTriage, "demander", lambda self, prompt: "pas du json")
    monkeypatch.setattr(sys, "argv", ["tp2", "-f", chemin_faux])
    module.main()
    rapport = json.loads(Path(f"{chemin_faux}.triage.json").read_text(encoding="utf-8"))
    assert rapport["size"] > 0
