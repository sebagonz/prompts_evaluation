"""Initialize local secrets and provision a LiteLLM auditor user/key."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"
EXAMPLE_PATH = ROOT / ".env.example"


def read_env() -> dict[str, str]:
    values = {}
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            name, value = line.split("=", 1)
            values[name.strip()] = value.strip().strip('"').strip("'")
    return values


def local_proxy_url() -> str:
    """Usa el puerto publicado por Compose, con la misma precedencia de entorno."""
    settings = read_env() if ENV_PATH.exists() else {}
    port_text = os.environ.get("LITELLM_PORT", settings.get("LITELLM_PORT", "")) or "4001"
    try:
        port = int(port_text)
    except ValueError as error:
        raise RuntimeError("LITELLM_PORT debe ser un puerto entre 1 y 65535") from error
    if not 1 <= port <= 65535:
        raise RuntimeError("LITELLM_PORT debe ser un puerto entre 1 y 65535")
    return f"http://127.0.0.1:{port}"


def write_env(content: str) -> None:
    temporary = ENV_PATH.with_name(".env.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
    temporary.replace(ENV_PATH)
    ENV_PATH.chmod(0o600)


def set_env_value(name: str, value: str) -> None:
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    replacement = f"{name}={value}"
    for index, line in enumerate(lines):
        if line.startswith(f"{name}="):
            lines[index] = replacement
            break
    else:
        lines.append(replacement)
    write_env("\n".join(lines) + "\n")


def init() -> None:
    if ENV_PATH.exists():
        print(".env ya existe; no se modificó.")
        return
    content = EXAMPLE_PATH.read_text(encoding="utf-8")
    content = content.replace(
        "POSTGRES_PASSWORD=REEMPLAZAR_CON_VALOR_ALEATORIO",
        f"POSTGRES_PASSWORD={secrets.token_hex(24)}",
    ).replace(
        "LITELLM_MASTER_KEY=sk-REEMPLAZAR_CON_VALOR_ALEATORIO",
        f"LITELLM_MASTER_KEY=sk-{secrets.token_hex(32)}",
    ).replace(
        "LITELLM_SALT_KEY=sk-REEMPLAZAR_CON_VALOR_ALEATORIO",
        f"LITELLM_SALT_KEY=sk-{secrets.token_hex(32)}",
    ).replace(
        "UI_PASSWORD=REEMPLAZAR_CON_VALOR_ALEATORIO",
        f"UI_PASSWORD=Local-{secrets.token_hex(16)}!",
    )
    write_env(content)
    print(".env creado con secretos locales aleatorios (permisos 0600).")
    print("Exportá ANTHROPIC_API_KEY o OPENAI_API_KEY en la sesión antes de iniciar LiteLLM.")


def request(path: str, master_key: str, payload: dict | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Authorization": f"Bearer {master_key}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    action = urllib.request.Request(local_proxy_url() + path, data=body, headers=headers)
    try:
        with urllib.request.urlopen(action, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and path.startswith("/user/info?"):
            return {}
        detail = exc.read().decode("utf-8", errors="replace")
        detail = detail.replace(master_key, "[REDACTED]")[:250]
        raise RuntimeError(f"LiteLLM {path}: HTTP {exc.code}: {detail}") from exc


def bootstrap() -> None:
    if not ENV_PATH.exists():
        raise RuntimeError("Primero ejecutá: python3 litellm/setup.py init")
    settings = read_env()
    master = settings.get("LITELLM_MASTER_KEY", "")
    if not master.startswith("sk-"):
        raise RuntimeError("LITELLM_MASTER_KEY no está configurada en .env")
    user_id = settings.get("AUDIT_USER_ID", "prompt-auditor")
    user_email = settings.get("AUDIT_USER_EMAIL", "prompt-auditor@local.invalid")
    query = urllib.parse.urlencode({"user_id": user_id})
    user = request(f"/user/info?{query}", master)
    if user.get("user_id") != user_id:
        request("/user/new", master, {
            "user_id": user_id,
            "user_email": user_email,
            "user_role": "internal_user",
            "auto_create_key": False,
        })
        print(f"Usuario LiteLLM creado: {user_id}")
    else:
        print(f"Usuario LiteLLM existente: {user_id}")
    if settings.get("LITELLM_AUDITOR_KEY"):
        print("La clave virtual del auditor ya está en .env; no se regeneró.")
        return
    result = request("/key/generate", master, {
        "user_id": user_id,
        "key_alias": "prompt-auditor-local",
        "models": ["audit-anthropic", "audit-openai"],
    })
    key = result.get("key", "")
    if not key.startswith("sk-"):
        raise RuntimeError("LiteLLM no devolvió una clave virtual válida")
    set_env_value("LITELLM_AUDITOR_KEY", key)
    print("Clave virtual creada y guardada en .env; no se muestra en pantalla.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "bootstrap"])
    try:
        if parser.parse_args().action == "init":
            init()
        else:
            bootstrap()
    except (OSError, RuntimeError, urllib.error.URLError) as error:
        print(f"Error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
