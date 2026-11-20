# Copia manual del analizador al cliente

Actualizado: 20 de noviembre de 2026.

El proyecto se puede transportar copiando archivos, sin clonar el repositorio.
Conservar los nombres y la estructura relativa. Los tres scanners utilizan una
imagen: `prompt-security-poc:local`. El semántico se ejecuta por separado y el
consolidador transforma sus hallazgos a SARIF junto con los otros dos scanners.

## 1. Qué copiar para llevar la solución completa

Esta es la copia recomendada para poder construir, ejecutar, probar y consultar
la documentación en el cliente. Copiar también los archivos que comienzan con
punto, como `.dockerignore`, `.env.example` y el waiver de PromptSonar.

```text
prompts-analizer/
├── Dockerfile
├── .dockerignore
├── package.json
├── requirements-semantic.txt
├── docker-compose.yml
├── .env.example
├── scripts/
│   ├── scan-prompts.sh
│   ├── semantic_scan_prompts.py
│   ├── consolidate_scan_reports.py
│   ├── audit_rubric.md
│   ├── start-local.sh
│   ├── test_scan_prompts.py
│   ├── test_consolidate_scan_reports.py
│   ├── test_scan_pipeline.py
│   └── funcionamiento_harness.md
├── certs/
│   ├── README.md
│   └── kyndryl-ssl-inspection.crt
├── litellm/
│   ├── config.yaml
│   ├── start-proxy.sh
│   ├── setup.py
│   └── test_setup.py
├── prompts/
│   ├── banking_information_cacheable_template.txt
│   ├── example_markdown_prompt.md
│   ├── hardened_prompt.txt
│   ├── hardest_prompt.txt
│   ├── vulnerable_prompt.txt
│   └── .promptsonar-waivers.yaml
├── README.md
├── README analizador semantico.md
├── README_CATEGORIAS_PROMPTSONAR.md
├── instrucciones_correr_contenedor.md
├── CONTEXTO_PROYECTO.md
├── CONTEXTO_ANALIZADOR_SEMANTICO.md
├── COPIA_MANUAL_CLIENTE.md
└── diagramas/
    └── analizador-semantico.drawio
```

Los prompts enumerados son ejemplos de esta copia. Para analizar los del cliente,
agregarlos o sustituirlos en `prompts/`. El semántico solo incluye TXT visibles;
los scanners de patrones admiten TXT y Markdown.

La CA incluida es la CA pública del laboratorio. Antes de construir para otra
red, sustituirla por las CA públicas aprobadas por el cliente. El nombre del
archivo puede cambiar si conserva la extensión `.crt`. Mantener `certs/` aunque
no se necesiten CA adicionales; `certs/README.md` mantiene disponible la carpeta.
El Dockerfile copia esa carpeta y el proxy local la monta.

## 2. Cuáles son imprescindibles y cuáles opcionales

| Uso | Archivos necesarios |
| --- | --- |
| Construir la imagen con los tres scanners | `Dockerfile`, `.dockerignore`, `package.json`, `requirements-semantic.txt`, `certs/` y cuatro archivos de `scripts/`: `scan-prompts.sh`, `semantic_scan_prompts.py`, `consolidate_scan_reports.py`, `audit_rubric.md`. |
| Ejecutar mediante Compose con una imagen disponible | `docker-compose.yml`, una carpeta `prompts/` con las entradas y una carpeta vacía `reports/`. Crear `.env` en destino con la configuración de ese ambiente. |
| Usar el proxy ya existente del cliente | Lo anterior y sus variables de URL, clave virtual y alias. Ejecutar los servicios con `--no-deps`; no hace falta levantar el proxy/DB locales. |
| Levantar también LiteLLM y PostgreSQL locales | Agregar `.env.example`, `scripts/start-local.sh`, `litellm/setup.py`, `litellm/config.yaml`, `litellm/start-proxy.sh` y `certs/`. |
| Ejecutar pruebas simuladas del harness y la integración | Los tres `scripts/test_*.py`, además del código, rúbrica y dependencias de la imagen. |
| Probar el aprovisionamiento y puerto local sin API | `litellm/setup.py` y `litellm/test_setup.py`; se ejecutan con Python del host. |
| Conservar excepciones de los ejemplos | `prompts/.promptsonar-waivers.yaml`, junto con el prompt al que aplica. Revisar alcance y vencimiento antes de reutilizarlo. |
| Ejecutar luego en GitLab | `.gitlab-ci.yml`; no es necesario para una prueba manual local. |
| Publicar mediante el mecanismo corporativo existente | `registry.properties`, si ese mecanismo lo utiliza; no es necesario para `docker build` / `docker run` locales. |
| Documentar y explicar el flujo | Los README, contextos, `scripts/funcionamiento_harness.md`, esta guía y `diagramas/analizador-semantico.drawio`. |

El Dockerfile instala lo que encuentre en `scripts/`, por eso copiar la carpeta
completa es la opción más simple. Los tests y documentos no son necesarios para
una ejecución del scanner, pero permiten verificar y explicar la entrega.

## 3. Archivos que quedan fuera de la copia

- `.git/`, `.gitignore`, `.claude/` y `.DS_Store`: metadatos o configuración de desarrollo.
- `.env` del laboratorio: crear uno nuevo en destino, con las claves del cliente.
- `reports/` con resultados anteriores: crear la carpeta vacía para la prueba nueva.
- `__pycache__/`, `*.pyc` y `node_modules/`: cachés o dependencias instaladas.
- `Archive.zip`, `prompt-scanner-gs216303.zip` y `prompt-scanner-gs216303/`: paquetes históricos que no intervienen en este flujo.
- `renato/`, propuestas Word y la guía histórica `Guia_POC_Local_Control_1_01_Sin_LLM.md`: referencias fuera de la ejecución activa.
- `Dockerfile-analizador-semantico` y `docker-compose-ansemantic-litellm.yml`: alias de compatibilidad; el flujo actual usa `Dockerfile` y `docker-compose.yml`.

## 4. Copiar fuentes no elimina las descargas del build

La copia manual del proyecto no requiere Git en el host. Sin embargo, el
Dockerfile actual usa **Git dentro del contenedor de construcción** para
descargar `prompt-injection-auditor`, además de descargar paquetes Debian,
PromptSonar desde npm y las dependencias Python desde PyPI.

Si esa operación está permitida en el cliente, construir desde la raíz copiada,
con las CA correctas para su red:

```bash
docker build \
  --build-arg NPM_STRICT_SSL=true \
  --build-arg GIT_SSL_VERIFY=true \
  -t prompt-security-poc:local .
```

Si no se permiten Git o esas descargas durante el build, transportar la imagen
ya construida según el apartado siguiente. Copiar únicamente archivos Python
al host no instala Node, PromptSonar, el auditor externo ni las dependencias.

## 5. Alternativa: transportar la imagen ya construida

En un ambiente autorizado, construir la imagen con las CA del ambiente destino
y exportarla:

```bash
docker save -o prompt-security-poc-local.tar prompt-security-poc:local
```

Copiar ese TAR junto con la configuración, prompts y documentación. En el cliente:

```bash
docker load -i prompt-security-poc-local.tar
docker image inspect prompt-security-poc:local --format '{{.Os}}/{{.Architecture}}'
```

La arquitectura debe ser compatible con el motor Docker del cliente. Por ejemplo,
si el cliente usa Linux x86_64 y se construye desde una máquina ARM, construir
previamente para `linux/amd64` mediante `docker build --platform linux/amd64 ...`.

Con un proxy externo y la imagen cargada no se necesitan las fuentes de build
para ejecutar: los scanners, scripts y rúbrica ya están dentro de la imagen.
Las fuentes siguen siendo útiles para revisión y futuras reconstrucciones.
Los comandos `docker compose run` del apartado siguiente utilizan esa imagen.

Si también se utilizará la infraestructura local sin acceso a registros, deben
estar disponibles las imágenes de PostgreSQL y LiteLLM con las referencias
exactas indicadas en Compose. Transportar solo la imagen del analizador no
alcanza para levantar el stack completo sin acceso a registros. No usar
`start-local.sh` en este modo de imagen transportada: su último paso solicita
un build; con toda la infraestructura aprovisionada se puede usar
`docker compose up --no-build`.

## 6. Prueba manual con el proxy del cliente

Con la imagen construida o cargada, crear `.env` en destino con estos nombres;
reemplazar los valores de ejemplo con los del cliente:

```dotenv
LITELLM_BASE_URL=https://proxy-del-cliente/v1
LITELLM_AUDITOR_KEY=REEMPLAZAR_CON_CLAVE_VIRTUAL_DEL_CLIENTE
AUDIT_MODEL=REEMPLAZAR_CON_ALIAS_AUTORIZADO
FAIL_ON=critical
EXIT_ON_FINDINGS=true
```

Compose pasa esos valores al harness como `LITELLM_BASE_URL`, `LITELLM_API_KEY`
y `MODEL_NAME`. No se necesita la clave maestra del proxy ni una clave directa
del proveedor en los contenedores del analizador.

Desde la raíz copiada, preparar las carpetas y el usuario efectivo:

```bash
mkdir -p prompts reports
export LOCAL_UID="$(id -u)"
export LOCAL_GID="$(id -g)"
```

Para comprobar primero los scripts copiados con respuestas simuladas y sin red:

```bash
docker run --rm --network none --entrypoint python3 \
  -v "$PWD/scripts:/tests:ro" -w /tests \
  prompt-security-poc:local -m unittest discover -v
```

Para ejecutar las tres fuentes y consolidar en pasos separados:

```bash
docker compose run --rm --no-deps prompt-static
docker compose run --rm --no-deps prompt-analyzer
docker compose run --rm --no-deps consolidate
```

El segundo comando **sí consulta al LLM** y puede generar costo. Los workers
guardan sus errores y difieren el código final al consolidador. Revisar el
resultado del tercer comando y `reports/prompt-security-scan-summary.json`:
`PASS`, `BLOCK` o `ERROR`. Un error técnico elimina el SARIF final.

El SARIF final es `reports/prompt-security-scan.sarif`. `FAIL_ON` se comparte
entre las tres fuentes; `critical` es el valor predeterminado. `none` publica
todas las severidades elegibles sin bloquear por severidad. Los parciales
semánticos no se publican como auditorías completas.

## 7. Prueba con infraestructura local completa

Con los archivos de LiteLLM copiados, Docker/Compose y Python 3.9 o superior
en el host para el aprovisionamiento, restaurar los
permisos que el medio de copia pueda haber perdido:

```bash
chmod +x scripts/start-local.sh scripts/scan-prompts.sh
```

Crear `.env` en destino con `python3 litellm/setup.py init`, configurar las
credenciales del proveedor de ese ambiente y ejecutar `./scripts/start-local.sh`.
El script inicia DB/proxy, aprovisiona la clave virtual y luego ejecuta los scans.
Este arranque sí puede consumir API. El puerto del host predeterminado es `4001`;
se puede cambiar con `LITELLM_PORT`.

Si se reutiliza una base diferente, una clave virtual de otra instancia no será
válida. El bootstrap actual conserva una clave no vacía sin comprobar su validez;
ante ese caso, vaciar `LITELLM_AUDITOR_KEY` en `.env`, volver a aprovisionarla y
recrear el contenedor auditor para que reciba la clave nueva.

## 8. Entrega para CI/Sonar, si se usa después de la prueba manual

Agregar `.gitlab-ci.yml` y, si lo requiere la publicación corporativa,
`registry.properties`. La versión de imagen prevista es `1.1.0`; construir y
publicarla en el registro que vaya a utilizar el cliente.

El semántico se habilita en CI con `RUN_SEMANTIC_SCAN=true` y variables
`LITELLM_BASE_URL`, `LITELLM_API_KEY` y `MODEL_NAME`. La importación del SARIF
requiere un job con `sonar-scanner` y la configuración del SonarQube del cliente.
La prueba manual de los scanners no requiere copiar estos archivos de CI.
