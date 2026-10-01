"""Analyse statique d'un échantillon : il est lu en octets, jamais exécuté."""

import hashlib
import math
import re
from collections import Counter

from tp2.utils.config import logger

try:
    import lief
except ImportError:  # lief absent : parse_binary renvoie un résultat vide
    lief = None

try:
    import magic
except ImportError:  # libmagic absent : on devine le type nous-mêmes
    magic = None

# Chaînes lisibles en ASCII et en UTF-16
RE_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
RE_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

# Les IOCs
RE_URL = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_DOMAINE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
RE_MUTEX = re.compile(r"(?:Global|Local)\\[\w\-{}.]{3,}")
RE_REGISTRE = re.compile(r"(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U))\\[\w\\ .\-{}]+", re.IGNORECASE)

# Flag ESGI{...} et phrases typiques d'une injection de prompt
RE_FLAG = re.compile(r"ESGI\{[^}\r\n]{1,100}\}")
RE_INJECTION = re.compile(
    r"ignore (all |the )?(previous|above)|ignore les instructions|system prompt|"
    r"you are now|tu es maintenant|score\s*[:=]\s*0",
    re.IGNORECASE,
)

# Extensions de fichiers qui ne sont pas des domaines
EXTENSIONS = {
    "dll", "exe", "sys", "bat", "txt", "dat", "log", "ini", "tmp", "cfg",
    "pdb", "lib", "obj", "cpp", "py", "js", "png", "jpg", "xml", "json",
    "bin", "html", "htm", "pdf", "doc", "docx", "xls", "xlsx", "ps1", "vbs", "hta", "rar",
}  # fmt: skip
# Valeurs d'exemple : de faux IOCs
FAUX_DOMAINES = {"example.com", "example.org", "example.net", "localhost", "test.com"}
FAUX_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def ip_valide(ip: str) -> bool:
    """Refuse les IP d'exemple (0.x, 127.x, 255.x)."""
    if ip in FAUX_IPS:
        return False
    return int(ip.split(".", 1)[0]) not in (0, 127, 255)


def domaine_valide(domaine: str) -> bool:
    """Refuse les noms de fichiers et les domaines d'exemple."""
    domaine = domaine.lower()
    if domaine in FAUX_DOMAINES or domaine.endswith(".example.com"):
        return False
    return domaine.rsplit(".", 1)[-1] not in EXTENSIONS


class Sample:
    """Un fichier à analyser (lecture seule)."""

    def __init__(self, path: str) -> None:
        """Lit tout le fichier en octets."""
        self.path = path
        with open(path, "rb") as fichier:
            self.data = fichier.read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "file_type": self.file_type(),
            "entropy": round(self.shannon_entropy(), 4),
        }

    def file_type(self) -> str:
        """Type du fichier avec libmagic (sinon on regarde les premiers octets)."""
        if magic is not None:
            try:
                return magic.from_buffer(self.data)
            except Exception as err:  # noqa: BLE001
                logger.warning(f"libmagic a échoué : {err}")
        if self.data[:2] == b"MZ":
            return "PE executable"
        if self.data[:4] == b"\x7fELF":
            return "ELF executable"
        return "data"

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def strings(self) -> list[str]:
        """Chaînes lisibles (ASCII et UTF-16) du fichier."""
        liste = [m.decode("ascii") for m in RE_ASCII.findall(self.data)]
        liste += [m.decode("utf-16-le") for m in RE_UTF16.findall(self.data)]
        return liste

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        texte = "\n".join(self.strings())
        urls = {u.rstrip(".,;)") for u in RE_URL.findall(texte)}
        ips = {i for i in RE_IP.findall(texte) if ip_valide(i)}
        domaines = {d.lower() for d in RE_DOMAINE.findall(texte) if domaine_valide(d)}
        # le nom d'hôte de chaque URL compte aussi
        for url in urls:
            hote = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
            if RE_DOMAINE.fullmatch(hote) and domaine_valide(hote):
                domaines.add(hote.lower())
        domaines -= ips
        return {
            "domains": sorted(domaines),
            "ips": sorted(ips),
            "urls": sorted(urls),
            "mutex": sorted(set(RE_MUTEX.findall(texte))),
            "registry": sorted({r.rstrip(" .") for r in RE_REGISTRE.findall(texte)}),
        }

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        resultat = {"format": "unknown", "imports": [], "exports": [], "sections": []}
        if lief is None:
            return resultat
        try:
            binaire = lief.parse(self.path)
            if binaire is None:  # ni PE ni ELF
                return resultat
            resultat["format"] = str(binaire.format).split(".")[-1]
            resultat["imports"] = sorted({f.name for f in binaire.imported_functions if f.name})
            resultat["exports"] = sorted({f.name for f in binaire.exported_functions if f.name})
            resultat["sections"] = [
                {"name": s.name, "size": s.size, "entropy": round(s.entropy, 3)} for s in binaire.sections
            ]
        except Exception as err:  # noqa: BLE001
            logger.warning(f"Lecture de {self.path} impossible avec lief : {err}")
        return resultat

    def find_flag(self) -> str:
        """Flag ESGI{...} trouvé dans le fichier ('' s'il n'y en a pas)."""
        for chaine in self.strings():
            trouve = RE_FLAG.search(chaine)
            if trouve:
                return trouve.group(0)
        return ""

    def has_injection(self) -> bool:
        """Vrai si le fichier contient une phrase de prompt injection."""
        return any(RE_INJECTION.search(chaine) for chaine in self.strings())
