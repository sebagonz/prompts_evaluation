# Ejecución en laboratorio SUSE / Linux

Requisitos: Docker Engine (o una alternativa compatible que ejecute
contenedores Linux) y Docker Compose v2.

```bash
docker version
docker compose version
docker compose config
```

Desde la raíz clonada por Git:

```bash
mkdir -p reports
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose build
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose run --rm prompt-security
```

Para analizar un prompt específico:

```bash
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" \
  docker compose run --rm prompt-security prompts/vulnerable_prompt.txt
```

Los resultados quedan en `reports/`. Un retorno no cero puede indicar findings
del análisis; revisar JSON/SARIF y no sólo el código de salida.

Además de los SARIF de PromptSonar, el contenedor genera
`*-pi-auditor.sarif`, listo para importarse como external issue en SonarQube:

```bash
sonar-scanner -Dsonar.sarifReportPaths=reports/prompts-vulnerable_prompt-pi-auditor.sarif
```

Para este POC la validación TLS de npm y Git está desactivada durante el build,
para tolerar la inspección SSL de la red corporativa. Antes de incorporar el
flujo a desarrollo se debe habilitar nuevamente e instalar el certificado raíz
corporativo.
