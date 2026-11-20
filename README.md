# Analizador de seguridad de prompts — Control 1.01

Integra tres fuentes en un único resumen y SARIF para SonarQube:
PromptSonar, prompt-injection-auditor y el auditor semántico con LLM juez.
Los tres usan **la misma imagen** `prompt-security-poc:local`, construida con
`Dockerfile`. PostgreSQL y LiteLLM son servicios de infraestructura con sus
propias imágenes. Los dos scanners de patrones siguen funcionando sin API.

El semántico corre en un proceso separado, revisa estáticamente TXT visibles
y envía su contenido al juez a través de LiteLLM. No ejecuta esos prompts como
una aplicación. Sus hallazgos requieren revisión humana.

## Levantar todo localmente

Exportar la clave del proveedor elegido en la terminal y ejecutar:

```bash
./scripts/start-local.sh
```

El script crea `.env` con secretos locales aleatorios si falta, inicia
PostgreSQL y LiteLLM, crea una clave virtual del auditor y levanta los scans y
la consolidación. El aprovisionamiento de usuario/clave no llama al modelo;
el servicio `prompt-analyzer` **sí consume API**. No se ejecutó ese servicio
contra un proveedor para validar esta integración.

Si `.env` ya está preparado, el arranque completo es:

```bash
mkdir -p reports
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose up --build
```

Compose ejecuta `prompt-static` y `prompt-analyzer` separados; `consolidate`
espera a ambos. Los workers registran sus errores y difieren el exit code al
consolidador. El estado/código final está en el contenedor `consolidate` y en
`reports/prompt-security-scan-summary.json`. LiteLLM permanece disponible en
`http://127.0.0.1:4001`; `docker compose down` detiene la infraestructura y
conserva su base de datos. No usar `--abort-on-container-exit` para este flujo:
los workers terminan antes que la consolidación.

`LITELLM_PORT` configura el puerto del host, por defecto `4001`, para convivir
con `giskard-poc` en `4000`. Compose y el aprovisionamiento de la clave virtual
leen la misma variable desde `.env` o desde la terminal. Si ese puerto también
está ocupado, usar por ejemplo `LITELLM_PORT=4002 ./scripts/start-local.sh`.
Dentro de Docker, el proxy sigue accesible como `http://litellm:4000/v1`.

## Ejecutar por separado

Solo patrones, sin levantar LiteLLM ni consultar proveedores:

```bash
docker compose build prompt-security
docker compose run --rm prompt-security prompts
```

Solo semántico, con el proxy ya iniciado y la clave virtual configurada:

```bash
docker compose run --rm --no-deps prompt-analyzer prompts
```

El argumento `prompts` reemplaza el comando de Compose y conserva el código
propio del semántico: `0` completo, `2` incompleto. Admite también un TXT
puntual. Una entrada Markdown se marca `NOT_APPLICABLE`, sin llamar al juez.
Para repetir únicamente la consolidación de los artefactos actuales:

```bash
docker compose run --rm --no-deps consolidate
```

Al usar un proxy externo, definir `LITELLM_BASE_URL`, `LITELLM_AUDITOR_KEY` y
`AUDIT_MODEL`, y ejecutar el semántico con `--no-deps`. No requiere PostgreSQL
ni LiteLLM locales. El antiguo `docker-compose-ansemantic-litellm.yml` incluye
la definición principal; `Dockerfile-analizador-semantico` queda como alias de
compatibilidad de la imagen unificada, sin instalar otro entorno.

## Reportes, política y trazabilidad

`reports/prompt-security-scan-summary.json` muestra por prompt los tres
analizadores, totales por severidad y estado semántico, más modelo, hash de
rúbrica, tiempos e identificador de corrida. stdout reúne las tres fuentes
por prompt y explica qué se publica o excluye.

`reports/prompt-security-scan.sarif` contiene un run por herramienta. El
semántico conserva regla, severidad, explicación, recomendación, condiciones
de impacto, archivo, rango de líneas, cita literal y ajustes de cita. Solo
exporta `findings` de auditorías completas `REVIEW`. Los `partial_findings`
quedan en el JSON original; un `ERROR` nunca equivale a un scan limpio.

`FAIL_ON` rige publicación y bloqueo para las tres fuentes. Por defecto es
`critical`; `none` publica todo lo elegible sin bloquear. `EXIT_ON_FINDINGS=false`
conserva `BLOCK` y devuelve `0`. Los errores técnicos siempre producen
`ERROR`, salida `2` y eliminan el SARIF final para evitar publicar un scan
incompleto. Las categorías y excepciones de PromptSonar siguen aplicándose
solo a esa herramienta.

Los intercambios entre procesos son `reports/static-scan-manifest.json`,
`reports/static-sarif/` y `reports/prompt_audit/summary.json`. El propio harness
reemplaza el resumen anterior al iniciar y publica el estado `RUNNING`,
`COMPLETE`, `ERROR` o `NOT_APPLICABLE`, junto con el código de salida. La
consolidación verifica ese estado, la cobertura completa y los hashes de los
TXT. Una corrida interrumpida permanece en `RUNNING` y no puede publicarse
como completa. No se genera un recibo adicional.
Los manifiestos usan rutas relativas al checkout para transferirse entre jobs.
No hay caché de auditorías: repetir el semántico puede volver a consumir API.
No ejecutar dos corridas concurrentes sobre la misma carpeta de reportes.

## GitLab

Los jobs `prompt_static_scan` y `prompt_semantic_scan` usan la misma imagen y
se ejecutan separados. `prompt_security_scan` recoge sus artefactos y consolida;
el job de Sonar importa el SARIF resultante. El semántico está deshabilitado
por defecto en CI para controlar consumo. Para habilitarlo, configurar:

- `RUN_SEMANTIC_SCAN=true`.
- `LITELLM_BASE_URL`, `LITELLM_API_KEY` (virtual, protegida/enmascarada) y `MODEL_NAME`.
- Opcionalmente los límites del harness documentados en [la guía semántica](<README analizador semantico.md>).

Construir y publicar previamente la imagen `plataformas/prompt-scanner:1.1.0`,
alineada en `.gitlab-ci.yml` y `registry.properties`. Este repositorio no ejecutó
publicación ni una pipeline remota durante la integración.

## Pruebas sin consumo de API

Se conserva `scripts/test_scan_prompts.py` del proyecto `giskard-poc` y se
agregan pruebas de consolidación e integración con respuestas simuladas.
La suite usa mocks y un servidor HTTP en loopback, sin proveedores:

```bash
docker run --rm --network none --entrypoint python3 \
  -w /opt/prompt-scanner/scripts prompt-security-poc:local \
  -m unittest discover -v
```

Para incluir la prueba de los scanners estáticos reales con el juez simulado,
agregar `-e RUN_STATIC_INTEGRATION=1` a `docker run`. Todo permanece sin red externa.

Para probar el checkout con la imagen ya descargada del proyecto anterior:

```bash
docker run --rm --network none --entrypoint python \
  -e LITELLM_LOCAL_MODEL_COST_MAP=true -e DO_NOT_TRACK=1 \
  -v "$PWD/scripts:/tests:ro" -w /tests prompt-auditor:local \
  -m unittest discover -v
```

## Plantilla reutilizable y caching

`prompts/banking_information_cacheable_template.txt` es una plantilla de
asistente bancario informativo basada en los límites de `hardest_prompt.txt`.
Incluye jerarquía de instrucciones, rechazo explícito de reclamos de autoridad,
datos no confiables, ausencia de herramientas y acciones externas, protección
de información sensible y contrato de salida JSON.

Para usarla, mantener **idéntico** todo el texto anterior a
`{{USER_QUESTION_JSON}}` entre llamadas. Reemplazar ese marcador por un objeto
JSON con una clave `question`, serializando y escapando el valor como string.
El objeto completo es dato no confiable; no insertar documentos, fechas,
IDs, usuarios, secretos ni otras variables en el prefijo.
Si la API admite cache breakpoints, ubicarlos después de la etiqueta fija
`<UNTRUSTED_DATA>` y antes del JSON de cada request. La etiqueta de cierre
queda después del JSON y no forma parte del prefijo cacheable. En una API con
mensajes separados, enviar las instrucciones hasta `REQUEST DATA BOUNDARY`
como mensaje de sistema y el bloque delimitado con el JSON como mensaje de
usuario, preservando ese orden. La activación real,
el tamaño mínimo cacheable y el TTL dependen del proveedor y del modelo; medir
aciertos y costo de escritura/lectura antes de habilitarlo en producción.

Ejemplo de payload para sustituir el marcador:

```json
{"question":"¿Qué es una transferencia bancaria?"}
```

La plantilla sigue siendo un archivo de prompt modular versionado en Git;
este repositorio no la empaqueta como Skill. El escaneo estático revisa la
plantilla, no demuestra la seguridad de un modelo en ejecución. Para escanear
este archivo puntualmente, usar `docker compose run --rm prompt-security
prompts/banking_information_cacheable_template.txt` y revisar ambos JSON, el
resumen y el SARIF con el umbral `FAIL_ON` elegido.

## Portabilidad

El host sólo necesita un motor de contenedores que ejecute imágenes Linux y
Docker Compose compatible con la Compose Specification. La distribución del
host (macOS, SUSE/SLES u otra Linux) no forma parte de la imagen: Node.js,
Python, Git y los scanners están dentro del contenedor.

En el laboratorio SUSE, validar antes de ejecutar:

```bash
docker version
docker compose version
docker info --format '{{.OSType}}'
```

El último comando debe devolver `linux`. Si el laboratorio usa Podman en vez
de Docker, se requiere que su integración Compose sea compatible; validar el
comando `compose config` indicado abajo antes de correr el POC.

## Ejecución

Desde la raíz del repositorio:

```bash
mkdir -p reports
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose build
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose run --rm prompt-security
```

El mapeo de UID/GID evita que los archivos de `reports/` queden propiedad de
root en SUSE/Linux. En macOS también es seguro usar los mismos comandos.

Para un archivo puntual:

```bash
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" \
  docker compose run --rm prompt-security prompts/vulnerable_prompt.txt
```

Los reportes se escriben en `reports/`:

```text
*-promptsonar.json
*-pi-auditor.json
prompt-security-scan.sarif
prompt-security-scan-summary.json
```

Un código distinto de cero puede significar que hubo hallazgos; verificar los
archivos de salida antes de considerarlo un fallo técnico.

## Ajuste de hallazgos para Sonar

Las siete categorías y su uso en esta integración se explican en
[README_CATEGORIAS_PROMPTSONAR.md](README_CATEGORIAS_PROMPTSONAR.md).

Los tres analizadores conservan todos sus hallazgos en JSON. El SARIF consolidado
que consume Sonar publica, por defecto, sólo la categoría `security` de
PromptSonar y los hallazgos de los tres analizadores con severidad `critical`.
`FAIL_ON` es el único umbral para **publicar en SARIF y bloquear el scan**.
Vale `critical` por defecto; admite `high`, `medium` y `low`. Por ejemplo,
`high` publica y bloquea hallazgos `high` y `critical`. `none` publica todas
las severidades elegibles, incluida `info`, sin bloquear por severidad.
Para publicar y bloquear desde `medium`:

```bash
FAIL_ON=medium LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" \
  docker compose run --rm prompt-security prompts/hardest_prompt.txt
```

stdout muestra por separado, para cada herramienta y prompt, los findings
publicados y los excluidos con su motivo. Antes del resumen se imprime el umbral
`FAIL_ON`; dentro del bloque de cada prompt se enumeran los findings enviados
a Sonar y los excluidos, con herramienta, severidad, regla y título. Un finding
excluido del SARIF sigue en el JSON para revisión. `EXIT_ON_FINDINGS=false`
permite que el proceso termine en `0` aunque el resumen registre `BLOCK`; no
cambia qué findings se publican.

`scripts/consolidate_scan_reports.py` es el punto de consolidación: convierte
el JSON del auditor, filtra el SARIF original de PromptSonar y el SARIF
convertido, los fusiona, resume la ejecución y calcula el gate. Este gate
determina el resultado local `PASS`/`BLOCK`; SonarQube aplica su propio quality
gate al importar el SARIF.

El wrapper `scan-prompts` le pasa al consolidado estas opciones (también se
puede ejecutar directamente con `python3 scripts/consolidate_scan_reports.py --help`):

| Opción | Uso y valor por defecto |
| --- | --- |
| `--target RUTA` | Etiqueta del archivo o directorio analizado; obligatoria. |
| `--report-set PROMPT PS_JSON PS_SARIF PI_JSON` | Entradas de un prompt; repetir por cada archivo; opcional si solo se consolida el semántico. |
| `--output-sarif RUTA` | SARIF consolidado; obligatoria. |
| `--output-summary RUTA` | Resumen JSON; obligatoria. |
| `--fail-on NIVEL` | Mínimo que se publica y bloquea: `critical` (predeterminado), `high`, `medium` o `low`. `none` publica todas las severidades elegibles sin bloquear por severidad. |
| `--promptsonar-categories CSV` | Categorías de PromptSonar admitidas para SARIF y gate; predeterminado `security`. |
| `--exit-on-findings` | Admite `true` o `false`. Devuelve `1` ante un bloqueo; predeterminado `true`. Con `false`, el resumen registra `BLOCK` y el proceso devuelve `0`. |
| `--pi-auditor-revision TEXTO` | Revisión registrada en el resumen; predeterminado `unknown`. |
| `--governance-failed PROMPT` | Marca un prompt bloqueado por la policy de PromptSonar; repetible. |
| `--static-manifest RUTA` | Consume los argumentos y reportes generados por el worker estático. |
| `--semantic-summary RUTA --semantic-root RUTA` | Importa explícitamente un resumen semántico y valida sus TXT originales. |
| `--scanner-error` | Marca error técnico de algún analizador: salida `2`, resumen `ERROR` y ningún SARIF final. |

Las excepciones de PromptSonar llegan en el campo `waived` del JSON. El
consolidado imprime qué findings publica y descarta, con sus motivos, por
herramienta y prompt y en el resumen final.

Para incluir otras categorías de PromptSonar en Sonar, definir
`PROMPTSONAR_SONAR_CATEGORIES=security,structure` en el job o al ejecutar
Compose. Las excepciones de reglas de PromptSonar se documentan en
`prompts/.promptsonar-waivers.yaml` y tienen vencimiento. El filtro SARIF
respeta el campo `waived` del JSON, porque PromptSonar 1.5.1 aún exporta al
SARIF los hallazgos exceptuados.

La excepción actual de `sec_rag_injection` se limita a
`prompts/hardest_prompt.txt`: el marcador `{{USER_INPUT}}` dispara esa regla,
pero en este template representa datos para la respuesta, no una consulta de
recuperación. Si el flujo incorpora RAG, se debe revisar la excepción antes de
usarla. `PI-NO-ROLEGUARD` permanece en el JSON y se publica en SARIF cuando
`FAIL_ON` se configura en `medium`, `low` o `none`.

## Archivos para el ambiente del cliente

Publicar la imagen construida con `Dockerfile`, `package.json`,
`requirements-semantic.txt`, `certs/` y `scripts/` completo, incluida la rúbrica. Copiar
también `.gitlab-ci.yml`, `registry.properties` y los prompts/excepciones que
correspondan. Para reproducir la infraestructura local, incluir `docker-compose.yml`,
`.env.example` y `litellm/`; no copiar `.env` ni claves de proveedores.

## Red corporativa y certificados

El build descarga dependencias npm/Python y el auditor desde GitHub.
Instala las CA públicas de `certs/` en el almacén del contenedor. Se incluyó
la CA de inspección Kyndryl ya utilizada en el proyecto anterior; LiteLLM
también la incorpora a su bundle al iniciar. Para otra
red, reemplazarla por las CA aprobadas allí. pip mantiene TLS verificado. Para este POC de
laboratorio, la validación TLS de npm y Git está desactivada por defecto para
permitir redes que inspeccionan SSL.

Cuando se incorpore este flujo a una solución de desarrollo, se debe revertir
esa excepción, instalar el certificado raíz corporativo y construir con TLS
habilitado:

```bash
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" \
  docker compose build --build-arg NPM_STRICT_SSL=true --build-arg GIT_SSL_VERIFY=true
```

Si el laboratorio no tiene salida a npm/GitHub, construir la imagen en un
entorno autorizado y transferirla como artefacto OCI con
`docker save` / `docker load`; Git por sí solo no elimina esas descargas del
build.

## Reproducibilidad y límites

PromptSonar está fijado en la versión `1.5.1`. El auditor externo conserva un
parámetro de build (`AUDITOR_REF`) que hoy apunta a `main`; antes de llevarlo a
una solución de desarrollo debe fijarse a un commit o tag revisado y conservar
la procedencia/SBOM de la imagen. El repositorio contiene jobs de escaneo y
publicación en Sonar, pero la ejecución en el entorno del cliente debe
validarse allí.
