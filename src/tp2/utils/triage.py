import json

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


class Triage:
    def __init__(self, path: str, backend: str) -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner()
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        matches = self.scanner.scan(sample.data)
        flag = sample.find_flag()

        # résumé court : les listes trop longues sont coupées
        summary = json.dumps(
            {
                "meta": meta,
                "iocs": {nom: valeurs[:20] for nom, valeurs in iocs.items()},
                "yara": matches,
                "bin": {"format": bininfo["format"], "imports": bininfo["imports"][:100]},
            },
            ensure_ascii=False,
        )

        # un fichier qui essaie de piéger le LLM ne lui est pas envoyé
        if sample.has_injection():
            logger.warning("Injection de prompt détectée : plan B sans LLM")
            texte = self.llm.fallback(summary)
        else:
            texte = self.llm.triage(summary)
        # verdict calculé sans LLM (sert de plan B et de contrôle)
        local = self.llm.valider(self.llm.fallback(summary))
        verdict = self.llm.valider(texte) or local

        return {
            **meta,
            "iocs": iocs,
            "imports": bininfo["imports"],
            "yara_matches": matches,
            "family_guess": verdict["famille"],
            "mitre_attack": verdict["mitre_attack"],
            "llm_summary": ", ".join(verdict["capacites"]) or "Aucune capacité identifiée",
            "score": self.borner(verdict["score_0_10"], local["score_0_10"]),
            "flag": flag,
        }

    def borner(self, score_llm: int, score_regles: int) -> int:
        """Le LLM ne décide pas seul : son score reste à +3 points des règles."""
        return min(10, max(score_regles, min(score_llm, score_regles + 3)))
