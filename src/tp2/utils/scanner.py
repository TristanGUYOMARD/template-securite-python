"""Scan YARA du contenu d'un fichier."""

from pathlib import Path

from tp2.utils.config import logger

try:
    import yara
except ImportError:  # yara absent : aucune règle ne se déclenche
    yara = None

# racine du projet (là où se trouve le dossier rules)
RACINE = Path(__file__).resolve().parents[3]


class YaraScanner:
    def __init__(self, rules_path: str = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path
        self.rules = self.compile()

    def compile(self):
        """Compile le fichier de règles et les autres .yar du même dossier."""
        if yara is None:
            return None
        principal = Path(self.rules_path)
        if not principal.is_file():  # chemin relatif : on cherche depuis la racine du projet
            principal = RACINE / self.rules_path
        fichiers = [principal]
        fichiers += sorted(f for f in principal.parent.glob("*.yar") if f != fichiers[0])
        sources = {}
        for fichier in fichiers:
            if fichier.is_file():
                # on lit nous-mêmes : yara n'aime pas les accents dans les chemins Windows
                sources[fichier.stem] = fichier.read_text(encoding="utf-8")
        if not sources:
            logger.warning(f"Aucune règle YARA trouvée pour {self.rules_path}")
            return None
        try:
            return yara.compile(sources=sources)
        except yara.SyntaxError as err:
            logger.error(f"Règles YARA invalides : {err}")
            return None

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        if self.rules is None:
            return []
        return sorted({match.rule for match in self.rules.match(data=data)})
