# POC local — Control 1.01 sin LLM

Analizador local de prompts `.txt` y `.md`. Ejecuta PromptSonar y
`prompt-injection-auditor` dentro de un contenedor Linux, sin LLM, GPU ni API
keys. La interfaz de este POC es la consola: no incluye GUI web ni puertos
expuestos.

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

Ambos analizadores conservan todos sus hallazgos en JSON. El SARIF consolidado
que consume Sonar publica, por defecto, sólo la categoría `security` de
PromptSonar y los hallazgos de ambos analizadores con severidad `critical`.
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

`scripts/consolidate_scan_reports.py` es el único script Python propio: convierte
el JSON del auditor, filtra el SARIF original de PromptSonar y el SARIF
convertido, los fusiona, resume la ejecución y calcula el gate. Este gate
determina el resultado local `PASS`/`BLOCK`; SonarQube aplica su propio quality
gate al importar el SARIF.

El wrapper `scan-prompts` le pasa al consolidado estas opciones (también se
puede ejecutar directamente con `python3 scripts/consolidate_scan_reports.py --help`):

| Opción | Uso y valor por defecto |
| --- | --- |
| `--target RUTA` | Etiqueta del archivo o directorio analizado; obligatoria. |
| `--report-set PROMPT PS_JSON PS_SARIF PI_JSON` | Entradas de un prompt; repetir por cada archivo; al menos una vez. |
| `--output-sarif RUTA` | SARIF consolidado; obligatoria. |
| `--output-summary RUTA` | Resumen JSON; obligatoria. |
| `--fail-on NIVEL` | Mínimo que se publica y bloquea: `critical` (predeterminado), `high`, `medium` o `low`. `none` publica todas las severidades elegibles sin bloquear por severidad. |
| `--promptsonar-categories CSV` | Categorías de PromptSonar admitidas para SARIF y gate; predeterminado `security`. |
| `--exit-on-findings` | Admite `true` o `false`. Devuelve `1` ante un bloqueo; predeterminado `true`. Con `false`, el resumen registra `BLOCK` y el proceso devuelve `0`. |
| `--pi-auditor-revision TEXTO` | Revisión registrada en el resumen; predeterminado `unknown`. |
| `--governance-failed PROMPT` | Marca un prompt bloqueado por la policy de PromptSonar; repetible. |
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

## Copia manual al ambiente del cliente: cambios de esta semana

Este listado es **sólo el delta** de estas sesiones para actualizar una copia
existente del proyecto. Conservá las mismas rutas relativas al copiarlo.

Para reconstruir y publicar la imagen del analizador, copiá estos archivos:

| Acción en el cliente | Archivo | Motivo |
| --- | --- | --- |
| Reemplazar | `Dockerfile` | Incluye el único Python propio en la imagen. |
| Reemplazar | `scripts/scan-prompts.sh` | Ejecuta los scanners y entrega sus reportes al consolidado. |
| Agregar | `scripts/consolidate_scan_reports.py` | Convierte, filtra y fusiona el SARIF; aplica `FAIL_ON` y genera el resumen. |

En esa copia, eliminá los tres scripts reemplazados:
`scripts/pi_auditor_to_sarif.py`, `scripts/merge_sarif_reports.py` y
`scripts/build_scan_summary.py`. La nueva imagen ya no los utiliza.

Si también vas a reproducir el análisis de `hardest_prompt.txt` en el checkout
del cliente, copiá `prompts/hardest_prompt.txt` y agregá
`prompts/.promptsonar-waivers.yaml` en el mismo directorio. La excepción de
`sec_rag_injection` está limitada a ese prompt.

Para llevar esta documentación actualizada, reemplazá `README.md` y agregá
`README_CATEGORIAS_PROMPTSONAR.md`. Los archivos `reports/` se generan al
escanear y no forman parte de la copia manual.

Después de copiar los scripts, reconstruí y publicá la imagen con el mecanismo
que ya usa el cliente: el job de GitLab consume la imagen publicada, por lo que
copiar sólo los scripts al checkout de prompts no cambia el scanner del runner.

## Red corporativa y certificados

El build descarga dependencias npm y el auditor desde GitHub. Para este POC de
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
