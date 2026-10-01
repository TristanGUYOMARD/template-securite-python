# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

Le TP1 est un IDS maison : il capture le trafic d'une interface réseau (ou lit un fichier pcap avec Scapy),
compte les paquets par protocole, détecte les attaques et écrit un rapport PDF ainsi qu'un `report.json`.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install
```

## Utilisation

Lancer le projet :

```bash
poetry run tp1
```

Sans option, le programme demande l'interface à écouter et capture pendant 30 secondes
(il faut les droits root, ou l'administrateur sous Windows avec Npcap).

Options :

| Option | Rôle |
| --- | --- |
| `--pcap` | analyser un fichier pcap au lieu d'écouter une interface |
| `--iface` | interface à écouter (sinon elle est demandée, ou lue dans `TP1_INTERFACE`) |
| `-c`, `--count` | nombre de paquets à capturer (0 = pas de limite) |
| `-t`, `--timeout` | durée de la capture en secondes (30 par défaut) |
| `--out` | fichier JSON de sortie (`report.json` par défaut), le PDF et le SVG sont écrits à côté |

Exemples :

```bash
# analyser un pcap (marche avec n'importe quel pcap / pcapng)
poetry run tp1 --pcap tp1-grp-4-191ba9.pcap --out out/report.json

# écouter eth0 pendant une minute
sudo poetry run tp1 --iface eth0 --timeout 60
```

## Ce que produit le programme

- `report.pdf` : synthèse, tableau des protocoles reçus (avec le nombre de paquets et la légitimité du trafic),
  graphique, et pour chaque attaque le protocole ainsi que la MAC et l'IP de l'attaquant.
- `report.json` : la même chose pour la correction automatique (`protocols`, `attacks`, `flag`).
  Pour chaque attaque : `type` et `attacker` (la MAC pour l'ARP spoofing, l'IP pour le scan de ports et l'injection SQL).
- `protocols.svg` : le graphique en version PyGal.
- `app.log` : les logs (le programme utilise `logger`, jamais `print`). Le niveau est réglé dans `src/config.py`.

## Comment les attaques sont détectées

- **ARP spoofing** (`arp_spoofing`) : la première MAC vue pour une IP est considérée comme la vraie ;
  une autre MAC qui annonce la même IP est l'attaquante.
- **Scan de ports** (`port_scan`) : une machine qui envoie des SYN vers au moins 10 ports différents d'une même cible.
- **Injection SQL** (`sql_injection`) : une requête TCP dont le contenu (décodé de l'URL) contient un motif connu
  (`' OR 1=1`, `UNION SELECT`, `; DROP`, `--`...). Le marqueur `ESGI{...}` est lu uniquement dans cette requête :
  le texte des autres paquets n'est jamais pris pour argent comptant (un pcap peut contenir des leurres).

Limites : une injection coupée sur plusieurs segments TCP n'est pas reconstituée, et le blocage de l'attaquant
(facultatif dans le sujet) n'est pas fait.

## Lancer dans un environnement isolé (Docker)

Le TP se joue dans un environnement jetable, pas directement sur l'hôte. Le `docker-compose.yml` lance le code
dans un conteneur sans réseau, avec un système de fichiers en lecture seule et sans aucune capability :

- docker compose build : construit l'image
- docker compose run --rm tests : lance les tests unitaires
- docker compose run --rm tp1 : analyse le pcap du dossier, rapports dans ./out
- PCAP=autre.pcap docker compose run --rm tp1 : même chose avec un autre pcap
- docker compose --profile live run --rm tp1-live : capture live sur le réseau interne "lab"

## Tests

```bash
poetry run pytest
```


## TP2 - Triage automatisé de malware

Outil d'analyse statique : l'échantillon n'est JAMAIS exécuté, il est seulement lu en octets (open(path, "rb")).
Il produit un rapport PDF et un rapport JSON : hashes, taille, entropie, type, IOCs (domaines, IP, URL, mutex, registre), imports (lief), règles YARA, hypothèse de famille, techniques MITRE ATT&CK, résumé, score de 0 à 10 et flag ESGI{...} s'il est présent dans le fichier.

Code (src/tp2) :
  - main.py : lit les options et lance le triage
  - utils/sample.py : classe Sample (hashes, entropie, IOCs, lief, flag)
  - utils/scanner.py : classe YaraScanner (règles du dossier rules)
  - utils/llm.py : classe LLMTriage (OpenRouter ou Ollama, plan B sans réseau)
  - utils/triage.py : classe Triage (enchaîne les étapes et calcule le score)
  - utils/report.py : classe Report (PDF avec fpdf2 et JSON)

Installation :
  - poetry install
  - libmagic doit être installé sur la machine (inclus dans l'image Docker)

Utilisation :
  - poetry run tp2 -f fichier.bin
  - rapports écrits à côté du fichier : fichier.bin.triage.pdf et fichier.bin.triage.json
  - option --out DIR : écrit les rapports dans un autre dossier
  - option --llm openrouter (par défaut) ou --llm ollama

LLM (facultatif) :
  - OpenRouter si la variable OPENROUTER_API_KEY existe (modèle meta-llama/llama-3.3-70b-instruct:free)
  - Ollama en local (http://localhost:11434, modèle qwen2.5:3b)
  - si le LLM ne répond pas ou répond mal, le verdict est calculé avec YARA, les IOCs et les imports
  - défense contre l'injection de prompt : données entre <<<DONNEES>>> et <<<FIN>>>, réponse JSON validée, fichier suspect jamais envoyé au LLM, score du LLM borné par celui des règles

Sécurité (à respecter) :
  - ne jamais lancer un échantillon sur sa machine : tout se fait dans Docker
  - les échantillons vont dans ./samples (ignoré par Git, jamais dans le zip)
  - docker compose build
  - docker compose run --rm tests-tp2 (tests avec données fictives)
  - docker compose run --rm tp2 (analyse de ./samples/faux.txt en lecture seule, sans réseau, utilisateur non root, rapports dans ./out)
  - autre fichier : SAMPLE=nom.bin docker compose run --rm tp2 (PowerShell : $env:SAMPLE="nom.bin"; docker compose run --rm tp2)

Règles YARA : rules/course_rules.yar (règle du cours) et rules/mes_regles.yar (règles personnelles, chargées avec la première).
