#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p reports
export LOCAL_UID="${LOCAL_UID:-$(id -u)}"
export LOCAL_GID="${LOCAL_GID:-$(id -g)}"
python3 litellm/setup.py init
docker compose up -d --wait postgres litellm
# Solo administra el usuario/clave virtual del proxy; no consulta al modelo.
python3 litellm/setup.py bootstrap
# A partir de aquí sí se auditan TXT y puede haber consumo de API.
docker compose up --build
