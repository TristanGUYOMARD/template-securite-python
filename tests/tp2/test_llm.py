import json

import pytest
import requests

from tp2.utils import llm as module
from tp2.utils.llm import LLMTriage

RESUME = json.dumps(
    {
        "meta": {"entropy": 7.5},
        "iocs": {"urls": ["http://x.test"], "mutex": [], "registry": [], "ips": [], "domains": []},
        "yara": ["Suspicious_Downloader"],
        "bin": {"imports": ["VirtualAlloc", "URLDownloadToFileA"]},
    }
)

BON = json.dumps({"famille": "F", "capacites": ["c"], "mitre_attack": ["T1"], "score_0_10": 5, "iocs": {}})


class Reponse:
    """Fausse réponse HTTP."""

    def __init__(self, contenu: dict) -> None:
        self.contenu = contenu

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self.contenu


def test_fallback():
    v = json.loads(LLMTriage().fallback(RESUME))
    assert v["famille"] == "Suspicious_Downloader"
    assert "T1055" in v["mitre_attack"]
    assert v["score_0_10"] == 3 + 1 + 2 + 1


def test_fallback_resume_invalide():
    v = json.loads(LLMTriage().fallback("pas du json"))
    assert v["famille"] == "unknown"
    assert v["score_0_10"] == 0


def test_valider():
    llm = LLMTriage()
    assert llm.valider("blabla " + BON)["score_0_10"] == 5
    assert llm.valider("pas du json") is None
    assert llm.valider('{"famille": "X"}') is None
    trop = json.dumps({"famille": "X", "capacites": [], "mitre_attack": [], "score_0_10": 99})
    assert llm.valider(trop) is None


def test_openrouter(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "cle")
    appels = []

    def faux_post(url, **kwargs):
        appels.append(kwargs["json"]["messages"][1]["content"])
        return Reponse({"choices": [{"message": {"content": BON}}]})

    monkeypatch.setattr(module.requests, "post", faux_post)
    assert LLMTriage("openrouter").triage(RESUME) == BON
    # le résumé est bien entouré de délimiteurs
    assert appels[0].startswith("<<<DONNEES>>>") and appels[0].endswith("<<<FIN>>>")


def test_ollama(monkeypatch):
    monkeypatch.setattr(module.requests, "post", lambda url, **k: Reponse({"message": {"content": BON}}))
    assert LLMTriage("ollama").triage(RESUME) == BON


def test_sans_cle_plan_b(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    v = json.loads(LLMTriage("openrouter").triage(RESUME))
    assert v["famille"] == "Suspicious_Downloader"


def test_sans_reseau_plan_b(monkeypatch):
    def boum(*args, **kwargs):
        raise requests.ConnectionError("pas de réseau")

    monkeypatch.setattr(module.requests, "post", boum)
    v = json.loads(LLMTriage("ollama").triage(RESUME))
    assert v["famille"] == "Suspicious_Downloader"


@pytest.mark.parametrize("reponse", ["n'importe quoi", '{"famille": "X"}'])
def test_reponse_invalide_plan_b(monkeypatch, reponse):
    monkeypatch.setattr(module.requests, "post", lambda url, **k: Reponse({"message": {"content": reponse}}))
    v = json.loads(LLMTriage("ollama").triage(RESUME))
    assert v["famille"] == "Suspicious_Downloader"
