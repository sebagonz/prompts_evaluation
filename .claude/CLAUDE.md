# Instrucciones del proyecto para Claude Code

El contexto del proyecto se carga desde @../CONTEXTO_PROYECTO.md. Contiene la arquitectura actual, el contrato del escáner y los puntos pendientes de validación en GitLab y SonarQube.

## Prioridades

- Mantén el alcance del Control 1.01: análisis estático de archivos de prompts `.txt` y `.md`, sin llamadas a LLM durante el escaneo.
- Distingue el POC local de la pipeline actual. La imagen Docker es la imagen del job de análisis; GitLab Runner ejecuta el job.
- Preserva los artefactos `reports/prompt-security-scan.sarif` y `reports/prompt-security-scan-summary.json`, porque el job de Sonar y la revisión operativa dependen de ellos.
- Trata los cambios locales existentes como trabajo del usuario. Revisa `git status` antes de editar y evita sobrescribir archivos ajenos a la tarea.
- No supongas que `renato/` forma parte del analizador activo: es material de referencia de otro escáner.

## Puntos de entrada

- Orquestador: `scripts/scan-prompts.sh`.
- Imagen: `Dockerfile` y `package.json`.
- Desarrollo local: `docker-compose.yml`.
- Consumo de imagen y Sonar: `.gitlab-ci.yml`.
- Publicación de imagen: `registry.properties` y el pipeline separado de `prompt-scanner-gs216303/`; su plantilla está fuera del repositorio.

## Validación de cambios

- Para Bash: `bash -n scripts/scan-prompts.sh`.
- Para Python: `python3 -m py_compile scripts/*.py`.
- Para Compose: `docker compose config`.
- Para cambios de CI, verificar los nombres reales de imagen, tags, variables y artefactos; no afirmar que la pipeline del cliente funciona sin ejecutarla allí.
- Si Docker no responde, comprobar primero el daemon o Colima antes de atribuir el fallo al Dockerfile.
