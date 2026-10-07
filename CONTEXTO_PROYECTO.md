# Contexto actual del proyecto — analizador de prompts

Actualizado: 6 de octubre de 2026. Este documento describe el estado observado en el repositorio, incluidas las modificaciones locales sin commit. Distingue lo implementado de lo que todavía depende del ambiente del cliente.

## Propósito y alcance

El proyecto implementa el **Control 1.01: revisión de seguridad de system prompts y prompt templates** antes de su uso y cuando cambian. Analiza archivos `.txt` y `.md` con dos herramientas estáticas, sin LLM, GPU ni claves de API para el análisis:

- **PromptSonar 1.5.1**: busca patrones de prompt injection, jailbreak, ofuscación, secretos/PII y permisos o flujos inseguros.
- **prompt-injection-auditor (`pi_scan.py`)**: revisa jerarquía de instrucciones, no divulgación, límites para contenido no confiable, uso de herramientas y confirmaciones.

El objetivo operativo actual es construir y publicar una imagen del analizador en el registro interno, usarla como **imagen de un job ejecutado por GitLab Runner**, generar evidencia JSON/SARIF y publicar el SARIF consolidado en SonarQube desde otro job. La imagen es el entorno del job; GitLab Runner es la infraestructura que ejecuta ese job.

El análisis es estático. Un resultado sin hallazgos no demuestra resistencia a ataques dinámicos. `renato/` documenta otro escáner, `ai-scan`, de alcance más amplio; no participa en el flujo activo de este analizador.

## Flujo implementado

```text
Repositorio con prompts/*.txt y *.md
  ├─ Dockerfile → imagen del analizador → registro interno / Harbor
  └─ GitLab CI, job prompt_security_scan (imagen del analizador)
       ├─ PromptSonar → JSON + SARIF temporal
       ├─ pi_scan.py → JSON
       └─ consolidado único → conversión, filtro, gate y fusión
            ├─ reports/prompt-security-scan.sarif
            └─ reports/prompt-security-scan-summary.json
            ↓ artifacts: reports/ (14 días)
     GitLab CI, job sonar_prompt_security_publish (otra imagen)
       └─ sonar-scanner → SonarQube, importación de SARIF
```

La pipeline raíz **consume** una imagen previamente publicada; no construye ni publica esa imagen. La publicación parece apoyarse en el paquete `prompt-scanner-gs216303.zip`, `registry.properties` y un pipeline separado con una plantilla corporativa. El repositorio no contiene la definición de esa plantilla, por lo que no se puede confirmar aquí cómo se construye o sube la imagen.

## Componentes y responsabilidades

| Ruta | Función actual |
| --- | --- |
| `Dockerfile` | Construye sobre `node:22-bookworm-slim`; instala Bash, Git y Python 3; instala PromptSonar por npm; clona `prompt-injection-auditor`; copia los scripts y define `scan-prompts` como entrypoint. |
| `package.json` | Declara `@promptsonar/cli` versión `1.5.1` y el comando npm `scan`. |
| `scripts/scan-prompts.sh` | Orquesta el escaneo de un archivo o un directorio recursivo de `.txt`/`.md`; normaliza rutas absolutas para el checkout de GitLab y entrega los reportes originales al consolidado. |
| `scripts/consolidate_scan_reports.py` | Único script Python propio: convierte el JSON del auditor a SARIF, filtra ambos SARIF por severidad/categoría/waiver, los fusiona, evalúa `FAIL_ON`, registra qué se publica y genera el resumen. |
| `.gitlab-ci.yml` | Define los jobs `prompt_security_scan` y `sonar_prompt_security_publish`, el paso de artefactos y los parámetros de SonarQube. |
| `docker-compose.yml` | Ejecución local: monta `prompts/` en solo lectura y `reports/` para salida; permite UID/GID del operador. |
| `prompts/` | Cuatro ejemplos: vulnerable, hardened, hardest y Markdown. Son entradas de demostración, no pruebas automatizadas. |
| `registry.properties` | Declara namespace, nombre y tag de imagen para la publicación. |
| `prompt-scanner-gs216303/.gitlab-ci.yml` | Pipeline separado que incluye `devsecops/devsecops-templates` → `/util/registry-image-upload.yml`. La carpeta extraída solo contiene metadatos; el ZIP incluye una copia del proyecto completo. |
| `README.md`, `instrucciones_correr_contenedor.md` | Guías de ejecución local y contenedor. |
| `README_CATEGORIAS_PROMPTSONAR.md` | Taxonomía de las siete categorías de PromptSonar 1.5.1 y uso del filtro de categorías de este proyecto. |
| `Guia_POC_Local_Control_1_01_Sin_LLM.md`, documentos Word | Contexto y propuestas de la fase POC; algunas afirmaciones sobre la ausencia de CI/CD o SonarQube ya no describen el estado actual. |
| `renato/` | Material de referencia de `ai-scan` para otros controles de IA; no se importa ni ejecuta desde el Dockerfile o la pipeline raíz. |

## Contrato del escáner

- Entrada: `scan-prompts [ruta]`; sin argumento usa `prompts`. Si recibe un directorio, busca recursivamente `.txt` y `.md` con esos sufijos en minúsculas.
- Salida persistente por prompt: `reports/<nombre>-promptsonar.json` y `reports/<nombre>-pi-auditor.json`. Los SARIF individuales se generan en un directorio temporal; el artefacto final es `reports/prompt-security-scan.sarif`.
- Salida agregada: `reports/prompt-security-scan-summary.json`, con `PASS`, `BLOCK` o `ERROR`, conteos por severidad y el código esperado.
- `FAIL_ON` es el único umbral de publicación en SARIF y bloqueo del scan para ambos analizadores; vale `critical` por defecto y admite `high`, `medium`, `low` y `none`. `none` publica todas las severidades elegibles sin bloquear por severidad. Las categorías y waivers de PromptSonar se respetan en ambos usos. `PROMPTSONAR_WAIVER` y `PROMPTSONAR_POLICY_FILE` son opcionales. PromptSonar publica sólo findings `security` por defecto (`PROMPTSONAR_SONAR_CATEGORIES`); los JSON completos se conservan. stdout y su resumen final separan los hallazgos incluidos y excluidos, con motivos.
- `prompts/.promptsonar-waivers.yaml` exceptúa `sec_rag_injection` únicamente para `hardest_prompt.txt` hasta el 6 de enero de 2027. El consolidado aplica el campo `waived` del JSON al SARIF, porque PromptSonar 1.5.1 todavía exporta los findings exceptuados a SARIF.
- `EXIT_ON_FINDINGS=true` por defecto: salida `0` sin hallazgos bloqueantes, `1` con hallazgos bloqueantes, `2` ante errores de ejecución. En la pipeline se fija `EXIT_ON_FINDINGS=false`, así que los hallazgos no fallan el job, pero los errores sí.
- `REPORTS_DIR` permite elegir la carpeta de salida. En GitLab se fija a `$CI_PROJECT_DIR/reports`.
- Si no hay archivos elegibles, el script sale con `0` sin crear el SARIF consolidado; el job posterior exige que exista y tenga contenido.

## GitLab CI y ambiente del cliente

1. `prompt_security_scan` usa `${REGISTRY}/${CI_REPO_IMAGE_NAME}:${CI_REPO_IMAGE_TAG}`, anula el entrypoint de la imagen, entra en `$CI_PROJECT_DIR` y ejecuta `scan-prompts "$PROMPTS_DIR"`. Publica `reports/` como artefacto incluso cuando el job falla; la retención configurada es de 14 días.
2. `sonar_prompt_security_publish` recibe los artefactos mediante `needs`, está configurado con `when: always`, comprueba que exista el SARIF y ejecuta `sonar-scanner` con `sonar.sarifReportPaths=reports/prompt-security-scan.sarif`. Usa `SONAR_SERVER` y `SONAR_TOKEN`, previstos como variables protegidas/enmascaradas en GitLab. Espera el quality gate hasta 600 segundos.
3. El job de Sonar usa actualmente `registry.intranet.local:5000/${DC_IMAGE_BUILD}` como imagen. La variable `SONAR_SCANNER_IMAGE` se declara, pero **no se usa**. La imagen efectiva debe contener `sonar-scanner`; esto no se puede comprobar desde este repositorio.
4. Los jobs necesitan acceso al registro interno y a SonarQube desde el runner, además de las credenciales del registro y las variables de Sonar configuradas fuera del repositorio. No hay reglas de ramas o merge requests en este YAML.

## Ejecución local

Desde la raíz del repositorio, con Docker/Compose y el daemon activo:

```bash
mkdir -p reports
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose build
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose run --rm prompt-security
```

Para un archivo, agregar por ejemplo `prompts/vulnerable_prompt.txt` al final de `docker compose run --rm prompt-security`. El contenedor local usa el checkout montado; el job de GitLab usa el checkout del runner y la herramienta instalada en `/workspace` dentro de la imagen.

## Estado verificado y pendientes

- Se inspeccionaron los archivos de código, Docker, Compose, CI, ejemplos y documentación presentes. Docker y Colima están operativos localmente; se construyó la imagen y se ejecutaron escaneos de extremo a extremo sobre `hardest_prompt.txt` y `vulnerable_prompt.txt`.
- En `hardest_prompt.txt`, PromptSonar produjo cuatro hallazgos en JSON: uno `high` exceptuado para ese archivo y tres recomendaciones no relacionadas con seguridad. `pi_scan.py` reportó `PI-NO-ROLEGUARD` (`medium`). Con `FAIL_ON=critical`, ninguno de estos findings se publica en Sonar; con `FAIL_ON=medium`, el del auditor sí se publica y el scan queda en `BLOCK`. `vulnerable_prompt.txt` sirve como control para comprobar que los hallazgos críticos siguen publicándose.
- La corrida local del directorio `prompts/` con valores por defecto procesó cuatro archivos y dejó diez resultados críticos en el SARIF consolidado (seis de PromptSonar y cuatro del auditor), provenientes de otros prompts de ejemplo. El resumen fue `BLOCK`; con `EXIT_ON_FINDINGS=false`, el proceso terminó en `0` para permitir la publicación posterior.
- Los logs aportados del cliente muestran que Sonar importó el SARIF anterior y luego falló por el quality gate. El filtrado nuevo todavía no fue probado en el ambiente del cliente.
- Hay una **desalineación de tags**: `registry.properties` declara `1.0.0-node22-nvm0.40.3`; la pipeline consumidora solicita `1.0.1`. Verificar qué tag se publicó realmente antes de ejecutar CI.
- La publicación de imagen depende de una plantilla corporativa externa que no está en el checkout; confirmar su uso de `registry.properties`, el contexto de build y las credenciales.
- La imagen de publicación en Sonar no coincide con `SONAR_SCANNER_IMAGE`; confirmar que la imagen usada realmente incluya `sonar-scanner` o ajustar el job.
- El auditor se clona desde `main` y no hay `package-lock.json`; la construcción no fija completamente las dependencias. El Dockerfile además desactiva por defecto la validación TLS de npm y Git para el laboratorio. Para una imagen aprobada por el cliente, fijar la revisión del auditor y definir la política de certificados/artefactos.
- Los escáneres reciben rutas absolutas del checkout. El conversor del auditor conserva la ruta del reporte en `artifactLocation.uri`; verificar en una corrida real que SonarQube asocie los findings a los archivos de `sonar.sources` después de transferir el artefacto entre jobs.
- La política final de bloqueo se mantiene en modo de observación (`EXIT_ON_FINDINGS=false`). El resultado del quality gate de Sonar es una decisión separada y depende de la configuración del servidor.

## Objetivos próximos

1. Validar en el ambiente del cliente la construcción/publicación de la imagen y alinear el tag publicado con el consumido por GitLab.
2. Ejecutar la pipeline sobre los prompts de ejemplo y uno representativo del cliente; conservar JSON, resumen, SARIF y logs de ambos jobs.
3. Confirmar la importación de findings por archivo en SonarQube y decidir el umbral de bloqueo, las excepciones y el gobierno del quality gate.
4. Revisar si `PI-NO-ROLEGUARD` requiere una formulación más explícita en el prompt o una excepción acotada: el auditor usa patrones de texto y no reconoce la frase actual sobre reclamos de autoridad. Validar en el cliente el SARIF filtrado antes de adoptar los resultados como definitivos.
