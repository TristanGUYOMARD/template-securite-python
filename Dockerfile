# Environnement jetable et isolé pour le TP1 (Scapy) et le TP2 (triage de malware, sans exécution).
# Le code du projet n'est PAS copié dans l'image : il est monté en lecture seule (voir docker-compose.yml).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    PYTHONPATH=/app:/app/src

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump iproute2 libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install "poetry>=2,<3" ruff

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --no-interaction

# Utilisateur non privilégié par défaut (le mode capture "live" repasse en root avec NET_RAW uniquement).
RUN useradd --create-home --uid 1000 lab
USER lab

CMD ["python", "-m", "tp1.main", "--help"]
