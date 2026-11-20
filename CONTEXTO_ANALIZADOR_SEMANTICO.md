# Contexto del analizador semántico: estructura y funciones

**Proyecto:** `prompts-analizer` (harness incorporado desde `giskard-poc`).

**Actualizado:** 5 de noviembre de 2026.

**Fuente de esta descripción:** código actual de `scripts/semantic_scan_prompts.py`,
`scripts/consolidate_scan_reports.py`, `Dockerfile` y `docker-compose.yml`.

## 1. Propósito y alcance

El analizador revisa estáticamente los TXT que contienen prompts de sistema.
Un LLM juez propone defectos de las instrucciones; Pydantic valida su respuesta
y el harness verifica las citas contra el archivo original. No ejecuta el
prompt objetivo como una aplicación ni comprueba herramientas o permisos reales.
Los hallazgos requieren revisión humana; `NO_FINDINGS` no certifica seguridad.

La selección admite una carpeta o un TXT puntual. Incluye extensiones `.txt`
sin distinguir mayúsculas y excluye archivos ocultos y enlaces simbólicos.
Markdown queda para los scanners de patrones. Una selección sin TXT elegibles
es `NOT_APPLICABLE`; un TXT vacío, demasiado largo o fallido es un error.

El harness genera JSON. El **consolidador** transforma los hallazgos semánticos
en SARIF y aplica el mismo `FAIL_ON` que a PromptSonar y pi-auditor.

## 2. Archivos y servicios

| Archivo | Responsabilidad |
| --- | --- |
| [scripts/semantic_scan_prompts.py](scripts/semantic_scan_prompts.py) | CLI, ciclo de vida, selección, concurrencia, llamadas al juez, validación, JSON y consola. |
| [scripts/audit_rubric.md](scripts/audit_rubric.md) | Rúbrica de 19 reglas locales `SEM-*`, con ejemplos y contraejemplos. |
| [scripts/consolidate_scan_reports.py](scripts/consolidate_scan_reports.py) | Lee las tres fuentes, valida el resumen semántico, convierte a SARIF, filtra y calcula el gate. |
| [scripts/scan-prompts.sh](scripts/scan-prompts.sh) | Ejecuta PromptSonar y pi-auditor; puede diferir la consolidación mediante un manifiesto. |
| [Dockerfile](Dockerfile) y [requirements-semantic.txt](requirements-semantic.txt) | Una imagen para los tres scanners; `semantic-scan` apunta directamente al harness. |
| [docker-compose.yml](docker-compose.yml) | Workers separados, LiteLLM/PostgreSQL y consolidación posterior. |
| [scripts/start-local.sh](scripts/start-local.sh) | Prepara secretos, inicia infraestructura, aprovisiona la clave virtual y levanta el flujo. |
| [litellm/setup.py](litellm/setup.py) | Configuración local y aprovisionamiento administrativo, sin consultar al modelo. |
| [scripts/funcionamiento_harness.md](scripts/funcionamiento_harness.md) | Explicación detallada de mensajes, reintentos y evidencia. |
| [diagramas/analizador-semantico.drawio](diagramas/analizador-semantico.drawio) | Diagrama editable con tres páginas: flujo, funciones y contratos/SARIF. |

| Servicio Compose | Ejecuta | ¿Consulta al LLM? |
| --- | --- | --- |
| `prompt-static` | PromptSonar y pi-auditor. | No. |
| `prompt-analyzer` | `semantic-scan --defer-exit prompts`. | Sí, si hay TXT y configuración válida. |
| `consolidate` | Conversión, filtrado y unión de resultados. | No. |

Los tres servicios de análisis/consolidación usan `prompt-security-poc:local`.
LiteLLM y PostgreSQL tienen sus propias imágenes. El sufijo `-1` del nombre de
un contenedor representa su primera instancia. Los workers pueden ejecutarse
en paralelo; `consolidate` espera su finalización.

## 3. Jerarquía de llamadas

```text
semantic-scan [--defer-exit] [target]
└── cli()
    └── asyncio.run(main())
        ├── save_json()                         → resumen inicial RUNNING
        ├── await audit_prompts(report)
        │   ├── visible_txt_files()             → selección ordenada
        │   ├── required_env()                  → modelo, URL y clave
        │   ├── asyncio.Semaphore(N)
        │   ├── create_task(run_prompt_agent()) → una tarea por TXT
        │   │   └── await audit_file()
        │   │       ├── AuditJudgement / CitationRepair + provider_schema()
        │   │       ├── await litellm.acompletion()
        │   │       ├── verify_finding_evidence() → report_finding()
        │   │       └── citation_repair_message() / verify_repair_coverage()
        │   ├── asyncio.as_completed()          → resultados según terminan
        │   ├── save_json()                     → por TXT y resúmenes
        │   └── render_findings_table()         → stdout
        └── save_json()                         → estado y exit_code finales

Proceso separado: consolidate_scan_reports.main()
├── semantic_inputs()                           → estado, cobertura y hashes
├── convert_semantic_report()                    → SARIF semántico
├── process_tool(..., tool="semantic", fail_on)  → mínimo de publicación/gate
├── merge_runs()                                 → tres fuentes
└── write_json_atomically()                      → SARIF + resumen unificados
```

`verify_evidence()` es un helper para validar todas las citas y se usa también
en pruebas. El camino principal de `audit_file()` llama a
`verify_finding_evidence()` por hallazgo para poder conservar los válidos
cuando otros necesitan corrección.

## 4. Modelos de datos

Estos modelos Pydantic usan validación estricta y rechazan campos adicionales.
Los esqueletos resumen sus campos; las restricciones completas están en el código.

```python
class Finding(BaseModel):
    rule_id: RuleId                # Uno de los 19 IDs de la rúbrica.
    severity: Severity             # low | medium | high | critical.
    title: str
    explanation: str
    recommendation: str
    impact_conditions: str
    line_number: int               # >= 1; numeración de líneas desde 1.
    evidence: str                  # Cita literal, no vacía.

class AuditJudgement(BaseModel):
    summary: str
    findings: list[Finding]        # Puede estar vacía.
    limitations: list[str]         # Al menos una limitación no vacía.

class FindingReplacement(BaseModel):
    index: int                     # Índice del candidato; desde 0.
    line_number: int
    evidence: str

class FindingWithdrawal(BaseModel):
    index: int
    reason: str

class CitationRepair(BaseModel):
    replacements: list[FindingReplacement]
    withdrawals: list[FindingWithdrawal]

class IncompleteAuditError(ValueError):
    def __init__(self, message: str, partial_findings: list[dict]):
        ...                       # Conserva solo hallazgos con citas verificadas.
```

Los validadores `Finding.not_blank()`, `AuditJudgement.summary_not_blank()` y
`AuditJudgement.limitations_not_blank()` rechazan los textos compuestos solo
por espacios. `line_number`, `index` y listas tienen las restricciones declaradas
en sus campos. Una corrección debe cubrir exactamente los índices rechazados.

## 5. Funciones principales del harness

Las firmas siguientes corresponden al código actual. `...` representa el
cuerpo omitido: es un mapa de lectura, no una implementación alternativa.

```python
def cli() -> int:
    ...

async def main() -> None:
    """Publica el estado de la corrida desde el inicio, incluso si falla el setup."""
    ...

async def audit_prompts(report: dict) -> None:
    """Orquesta agentes por prompt y publica reportes acumulados."""
    ...

async def run_prompt_agent(index: int, path: Path, total: int, semaphore: asyncio.Semaphore, prompts_dir: Path, rubric: str, model: str, base_url: str, api_key: str, max_output_tokens: int, timeout: float, max_attempts: int, max_input_chars: int, use_json_schema: bool) -> tuple[int, dict]:
    """Ejecuta un agente aislado por prompt y devuelve su resultado al orquestador."""
    ...

async def audit_file(path: Path, prompts_dir: Path, rubric: str, model: str, base_url: str, api_key: str, max_output_tokens: int, timeout: float, max_attempts: int, max_input_chars: int, use_json_schema: bool=True) -> dict:
    """Audita un TXT, con reintentos solo ante JSON o citas inválidas."""
    ...
```

### `cli()`: entrada de consola

Lee `target` y `--defer-exit`. Un target explícito reemplaza `PROMPTS_DIR`.
Ejecuta `main()` y devuelve el código del harness. Con `--defer-exit` fija
`FAIL_ON_FINDINGS=0` y permite que la CLI termine en cero aunque `main()`
registre un error técnico; el JSON conserva `exit_code=2`. Así la consolidación
puede correr, mostrar los errores y devolver el código final del flujo.

### `main()`: ciclo de vida de la corrida

Crea `run_id` y publica los resúmenes iniciales con `status=RUNNING` antes
de validar credenciales o auditar archivos. Llama a `audit_prompts(report)`,
recoge su código o una excepción inicial y guarda el estado final y `exit_code`.
Los errores iniciales se redactan con `safe_error()`. Una interrupción antes
del cierre deja `RUNNING`; el consolidador rechaza ese resumen.

La creación/escritura inicial del resumen debe poder completarse. Un fallo de
permisos o almacenamiento en ese punto puede impedir generar un reporte de error.

### `audit_prompts(report)`: orquestador

`report` es un diccionario compartido por referencia con `main()`. Descubre
TXT, valida configuración, carga la rúbrica y su hash, y crea una tarea por
archivo. El semáforo limita las llamadas concurrentes. Recibe resultados con
`as_completed()`, pero los ubica por índice para conservar el orden original
en JSON. Solo el orquestador escribe los reportes compartidos.

Actualiza `results`, `counts`, tiempos y duración; muestra progreso, tablas y
archivos con error. Si no hay TXT devuelve `NOT_APPLICABLE` sin exigir una
clave ni consultar al juez. Si falta la carpeta, la corrida termina en error.

### `run_prompt_agent(...)`: aislamiento por archivo

| Parámetro | Uso |
| --- | --- |
| `index`, `path`, `total` | Posición original, TXT y cantidad total; permiten ordenar resultados y mostrar progreso. |
| `semaphore` | Cupos compartidos para concurrencia. |
| `prompts_dir` | Base para calcular la ruta relativa del TXT. |
| `rubric`, `model`, `base_url`, `api_key` | Contexto del juez y acceso al proxy. |
| Límites y `use_json_schema` | Se transmiten a `audit_file()` sin crear otra política de reintentos. |

Entra al semáforo y llama a `audit_file()`. Convierte una excepción en un
resultado `ERROR` para ese archivo sin cancelar los demás. Añade inicio, fin
y duración; devuelve `(index, record)`. La duración del agente excluye la espera
por el semáforo. `IncompleteAuditError` permite conservar `partial_findings`.

### `audit_file(...)`: una auditoría y sus intentos

| Parámetro | Uso |
| --- | --- |
| `path`, `prompts_dir` | Archivo y base de su ruta relativa. |
| `rubric` | Instrucciones del juez; contiene las reglas de auditoría. |
| `model` | Alias del proxy; el SDK usa `openai/{model}` para el cliente compatible. |
| `base_url`, `api_key` | Endpoint y clave virtual del proxy. |
| `max_output_tokens`, `timeout` | Límite de salida y segundos por llamada. |
| `max_attempts` | Máximo total de llamadas para ese TXT, incluidas correcciones. |
| `max_input_chars` | Rechaza archivos que exceden ese tamaño; no los trunca. |
| `use_json_schema` | Envía o no `response_format` con esquema estricto. |

Lee con `utf-8-sig`, rechaza un TXT vacío o demasiado largo y numera las líneas.
El mensaje `system` del juez contiene rúbrica y esquema; el mensaje `user`
contiene el prompt objetivo delimitado como dato no confiable. El rol que
recibe el juez no cambia el rol de sistema previsto para ese TXT en su aplicación.

La única llamada al modelo está en `await litellm.acompletion(**request)`.
La petición usa `num_retries=0`: el SDK no añade reintentos automáticos.

- Una respuesta truncada, JSON inválido o un esquema inválido puede activar otra auditoría completa.
- Citas rechazadas activan una reparación dirigida: corregir o retirar solo esos índices; se conservan los válidos.
- Cada índice debe corregirse o retirarse exactamente una vez; no se aceptan hallazgos nuevos en la reparación.
- Los errores de autenticación/conexión salen hacia `run_prompt_agent()`; no usan el reintento de validación.
- Si se agotan los intentos, lanza `IncompleteAuditError` con el mejor conjunto parcial de citas verificadas.

Devuelve el registro del TXT con `REVIEW` o `NO_FINDINGS`, hash, modelo,
resumen, hallazgos, limitaciones, intentos y uso de tokens cuando se informa.
La validación literal no confirma que la interpretación semántica sea correcta.

## 6. Funciones auxiliares del harness

### Selección, configuración y esquema

```python
def required_env(name: str) -> str:
    """Lee una variable obligatoria; falla antes de iniciar la corrida."""
    ...

def visible_txt_files(directory: Path, allow_empty: bool=False) -> list[Path]:
    """Lista los TXT visibles de forma estable, excluyendo enlaces y ocultos."""
    ...

def provider_schema(schema: dict) -> dict:
    """Quita restricciones JSON Schema que algunos proveedores no aceptan."""
    ...
```

| Función | Parámetros principales y efecto |
| --- | --- |
| `required_env()` | `name`: nombre de la variable; quita espacios y falla si está vacía. |
| `visible_txt_files()` | `directory`: carpeta o archivo. `allow_empty=False` exige al menos un TXT; el orquestador usa `True` para permitir `NOT_APPLICABLE`. Devuelve rutas ordenadas. |
| `provider_schema()` | `schema`: copia recursiva del esquema, quitando restricciones que ciertos proveedores no aceptan. Pydantic sigue validando con el esquema completo. |

### Evidencia y correcciones

```python
def verify_finding_evidence(finding: Finding, lines: list[str]) -> dict:
    """Resuelve solo citas exactas y no ambiguas; devuelve el hallazgo publicable."""
    ...

def verify_evidence(judgement: AuditJudgement, lines: list[str]) -> None:
    """Contrasta todas las citas con las líneas originales del archivo."""
    ...

def citation_repair_message(judgement: AuditJudgement, invalid: dict[int, str], lines: list[str], schema: dict) -> str:
    """Pide corregir solo citas rechazadas, sin reenviar la respuesta cruda."""
    ...

def verify_repair_coverage(repair: CitationRepair, invalid_indices: set[int]) -> None:
    """Cada índice rechazado debe corregirse o retirarse una sola vez."""
    ...
```

| Función | Parámetros principales y efecto |
| --- | --- |
| `verify_finding_evidence()` | `finding` y `lines` originales. Rechaza citas con patrones de claves; acepta una cita en su línea, corrige a otra línea solo si la coincidencia es única o acepta un tramo único de dos líneas contiguas. Devuelve el hallazgo con metadatos de ajuste. |
| `verify_evidence()` | `judgement` y `lines`: verifica todos los hallazgos; lanza excepción ante una cita inválida. No devuelve la colección de ajustes. |
| `citation_repair_message()` | `judgement`, `invalid` (índice → motivo), `lines`, `schema`: construye el pedido dirigido sin reenviar la respuesta cruda. Una línea larga o con patrones de claves se sustituye por una referencia al documento original. |
| `verify_repair_coverage()` | `repair`, `invalid_indices`: rechaza índices faltantes, adicionales o duplicados entre reemplazos y retiros. |

Los ajustes posibles son `citation_adjustment=unique_exact_line` o
`adjacent_span`. Pueden agregarse `model_line_number` y `end_line_number`.
No se reparan citas por similitud, traducción ni cambios de puntuación.

### Serialización y diagnóstico

```python
def report_finding(finding: Finding) -> dict:
    """Prepara un hallazgo verificable para JSON, ocultando claves narrativas."""
    ...

def redact_sensitive_text(value: str) -> str:
    """Oculta patrones de claves reconocidos en campos narrativos."""
    ...

def save_json(path: Path, record: dict) -> None:
    """Escribe JSON primero en un temporal y luego reemplaza el destino."""
    ...

def safe_error(error: Exception, secrets_to_hide: list[str]) -> str:
    """Reduce el detalle del error y redacta claves antes de publicarlo."""
    ...

def validation_reason(error: ValidationError | ValueError) -> str:
    """Resume fallas de validación sin copiar la salida cruda del juez."""
    ...
```

| Función | Parámetros principales y efecto |
| --- | --- |
| `report_finding()` | `finding`: transforma el modelo en diccionario y redacta sus textos narrativos. La evidencia se conserva literal y se controla antes de publicarla. |
| `redact_sensitive_text()` | `value`: oculta patrones reconocidos de claves `sk-…` y `AKIA…`; no es un detector completo de secretos. |
| `save_json()` | `path`, `record`: crea directorios, escribe un temporal y reemplaza el destino. No admite dos corridas escribiendo en la misma carpeta compartida. |
| `safe_error()` | `error`, `secrets_to_hide`: elimina secretos conocidos, aplica los patrones y limita el detalle del diagnóstico. |
| `validation_reason()` | `error`: resume ubicaciones/tipos de Pydantic o el mensaje de un `ValueError`, sin copiar la respuesta cruda. |

### Presentación

```python
def format_elapsed(milliseconds: int) -> str:
    """Presenta un tiempo transcurrido como horas:minutos:segundos.milisegundos."""
    ...

def parse_rule_titles(rubric: str) -> dict[str, str]:
    """Obtiene ID y título de las cabeceras de regla de la rúbrica."""
    ...

def render_findings_table(report: dict, color: bool, width: int=110, rule_titles: dict[str, str] | None=None) -> str:
    """Dibuja el resumen de consola; no modifica el reporte JSON."""
    ...
```

| Función | Parámetros principales y efecto |
| --- | --- |
| `format_elapsed()` | `milliseconds`: devuelve `HH:MM:SS.mmm`. |
| `parse_rule_titles()` | `rubric`: extrae el título de cada regla `SEM-*` para mostrarlo sin duplicar la rúbrica en código. |
| `render_findings_table()` | `report`, `color`, `width`, `rule_titles`: devuelve texto, ordena por severidad/archivo/línea, separa parciales y lista errores por archivo. |

`render_findings_table()` contiene tres helpers internos de formato:
`clean(value)` limpia controles de terminal; `border(left, middle, right)` arma
bordes; `row(values, severity=None)` envuelve celdas y aplica color opcional.
La tabla semántica muestra hallazgos completos **antes de `FAIL_ON`**. Una tabla
vacía con `Errores > 0` representa auditorías fallidas, no prompts aprobados.

## 7. Funciones del consolidador relacionadas con el semántico

```python
def semantic_inputs(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Valida la corrida actual y su cobertura; nunca consume un resumen viejo."""
    ...

def convert_semantic_report(record: dict[str, Any], uri: str, metadata: dict[str, Any]) -> dict[str, Any]:
    """Exporta propuestas completas, conservando evidencia y trazabilidad."""
    ...

def process_tool(report: dict[str, Any], sarif: dict[str, Any], tool: str, categories: set[str], fail_on: str) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    ...

def reaches(severity: str, minimum: str) -> bool:
    ...

def merge_runs(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Agrupa los runs por herramienta y conserva los resultados y reglas únicos."""
    ...

def main() -> int:
    ...
```

| Función | Parámetros principales | Qué hace |
| --- | --- | --- |
| `semantic_inputs()` | `args.semantic_summary`, `args.semantic_root` | Lee el resumen; exige estado final válido, cobertura completa, ausencia de duplicados, hashes actuales y coherencia entre estado y hallazgos. Devuelve registros por URI, metadatos y errores. |
| `convert_semantic_report()` | `record`, `uri`, `metadata` | Convierte `record.findings` a SARIF 2.1.0 con herramienta `semantic-prompt-auditor`. Conserva regla, archivo, líneas, evidencia, explicación, recomendación, condiciones de impacto y trazabilidad. |
| `process_tool()` | `report`, `sarif`, `tool`, `categories`, `fail_on` | Aplica el umbral común y devuelve SARIF filtrado, decisiones y cantidad bloqueante. Categorías y waivers son específicos de PromptSonar. |
| `reaches()` | `severity`, `minimum` | Compara severidades; con `minimum=none` no hay bloqueo por severidad. |
| `merge_runs()` | `documents` | Agrupa los SARIF por herramienta y une sus resultados y reglas. |
| `main()` | CLI mediante `parse_args()` | Reúne las tres fuentes, convierte/filtra, escribe resumen y SARIF finales o termina en `ERROR`. |

`read_json()`, `finding_fields()`, `matches()`, `report_summary()` y
`write_json_atomically()` apoyan lectura, correspondencia de hallazgos,
conteos y escritura. `build_summary()`, `print_decisions()` y `print_summary()`
producen el resumen JSON y stdout de las tres fuentes.

Los registros `ERROR` tienen `findings=[]`; `partial_findings` queda en el
JSON original. Si hay una auditoría incompleta o un error técnico, el flujo
consolidado devuelve `2` y elimina el SARIF final, incluso si otras fuentes
sí generaron hallazgos.

### Umbral común de publicación y bloqueo

| `FAIL_ON` / `--fail-on` | Se publica en el SARIF final | Bloqueo por severidad |
| --- | --- | --- |
| `critical` (predeterminado) | Critical. | Sí. |
| `high` | High y critical. | Sí. |
| `medium` | Medium, high y critical. | Sí. |
| `low` | Low y superiores. | Sí. |
| `none` | Todas las severidades elegibles. | No. |

Los JSON originales conservan todos los hallazgos. El wrapper estático pasa
`FAIL_ON` al manifiesto de esa corrida; la consolidación diferida reutiliza esa
política. Para reconsolidar un manifiesto con otro mínimo se debe pasar
`--fail-on` explícitamente al consolidador, además de sus entradas.

Conversión de nivel: `critical/high → error`, `medium → warning`,
`low/info → note`. La severidad original se conserva en propiedades; los
resultados semánticos incluyen `reviewRequired=true`. El quality gate de
SonarQube se evalúa por separado al importar el SARIF.

## 8. Parámetros de operación

| Variable | Valor o procedencia | Uso |
| --- | --- | --- |
| `PROMPTS_DIR` / argumento `target` | `/workspace/prompts` en el harness; Compose pasa `prompts` | Carpeta o TXT objetivo. |
| `REPORTS_DIR` | `/workspace/reports` en el harness y Compose | Base; el semántico agrega `prompt_audit/`. |
| `AUDIT_RUBRIC_PATH` | `/opt/prompt-scanner/scripts/audit_rubric.md` en la imagen | Rúbrica instalada. Fuera de la imagen el fallback del código es `/workspace/audit_rubric.md`. |
| `MODEL_NAME` | Obligatoria; Compose usa `AUDIT_MODEL`, por defecto `audit-anthropic` | Alias del juez publicado por el proxy. |
| `LITELLM_BASE_URL` | Obligatoria; Compose: `http://litellm:4000/v1` | API compatible del proxy, no del proveedor directo. |
| `LITELLM_API_KEY` | Obligatoria; Compose la obtiene de `LITELLM_AUDITOR_KEY` | Clave virtual autorizada en ese proxy. |
| `LITELLM_PORT` | `4001` | Puerto publicado en el host; el puerto interno sigue siendo `4000`. |
| `MAX_ATTEMPTS` | `2` | Llamadas máximas por TXT, incluyendo reparaciones. |
| `MAX_PARALLEL_PROMPTS` | `4` | Máximo de agentes dentro del semáforo. |
| `MAX_OUTPUT_TOKENS` | `6000` | Límite de salida de cada llamada. |
| `MAX_INPUT_CHARS` | `30000` | Máximo de caracteres de entrada. |
| `REQUEST_TIMEOUT_SECONDS` | `120` | Segundos por llamada. |
| `USE_JSON_SCHEMA` | `1` | Envía salida estructurada; `0` conserva validación posterior con Pydantic. |
| `FAIL_ON_FINDINGS` | `0`; `--defer-exit` lo fuerza a `0` | En modo independiente, `1` permite código `1` ante cualquier `REVIEW`. No filtra SARIF. |
| `FAIL_ON` | `critical` | Política común de publicación y bloqueo en la consolidación. |
| `EXIT_ON_FINDINGS` | `true` local; `false` en CI | Un `BLOCK` devuelve `1` o `0`; los errores técnicos siguen devolviendo `2`. |
| `FORCE_COLOR` / `NO_COLOR` | Control de consola | Activan o desactivan colores según la lógica del renderer. |
| `RUN_SEMANTIC_SCAN` | `false` en GitLab | Habilita explícitamente el job semántico para controlar consumo. |

Cada intento que llega al proveedor puede generar costo. Los hashes sirven
para trazabilidad y comprobación de fuentes; **no implementan una caché que
omita automáticamente archivos ya auditados**.

## 9. Estados y artefactos

Hay tres niveles de estado distintos:

| Nivel | Estados | Significado |
| --- | --- | --- |
| Corrida semántica (`summary.status`) | `RUNNING`, `COMPLETE`, `ERROR`, `NOT_APPLICABLE` | En curso, finalizada sin errores técnicos, fallida o sin TXT elegibles. `COMPLETE` admite hallazgos que requieren revisión. |
| TXT (`results[].status`) | `REVIEW`, `NO_FINDINGS`, `ERROR` | Hallazgos propuestos, ausencia de propuestas o auditoría incompleta. |
| Consolidación (`overall_result`) | `PASS`, `BLOCK`, `ERROR` | Gate común sin bloqueo, bloqueado por política o fallo técnico. |

El harness devuelve `2` ante errores; `1` si hay `REVIEW` y
`FAIL_ON_FINDINGS=1`; en otro caso `0`. `--defer-exit` difiere ese código al
consolidador y conserva el código real en el JSON. El estado global del
consolidador debe usarse para evaluar el flujo integrado.

```text
reports/
├── static-scan-manifest.json
├── static-sarif/
├── *-promptsonar.json
├── *-pi-auditor.json
├── prompt_audit/
│   ├── summary.json                        # Última corrida; se reemplaza al iniciar.
│   └── runs/<run_id>/
│       ├── summary.json                    # Resumen archivado de la corrida.
│       └── <ruta-relativa>.txt.json         # Resultado individual.
├── prompt-security-scan-summary.json        # Resumen de las tres fuentes.
└── prompt-security-scan.sarif               # SARIF final si no hay error técnico.
```

El resumen semántico incluye modelo, hash de rúbrica, fechas, duración,
conteos y resultados cuando se alcanzan esas fases. Un fallo inicial puede
no tener modelo, hash de rúbrica ni resultados por archivo. Los resultados
incluyen hash del TXT, citas, ajustes, tiempos y diagnóstico redactado; la
respuesta cruda del juez no se persiste. No hay `semantic_scan_job.py` ni
recibo semántico adicional. Evitar dos corridas sobre la misma carpeta de reportes.

## 10. Diagnóstico operativo y verificación

Un `401 Unauthorized` con token inexistente en la DB significa que la clave
virtual no es válida en el LiteLLM al que se está conectando. Los cuatro
archivos del log aportado terminaron así en `ERROR`; una tabla sin hallazgos
en ese caso no equivale a un análisis aprobado. `FAIL_ON` no provoca ese vacío.

El `bootstrap()` actual de `litellm/setup.py` conserva una clave existente en
`.env` sin validar que exista en la DB actual. Si la clave procede de otro
proxy o se recreó la base, se debe vaciar `LITELLM_AUDITOR_KEY`, ejecutar
`python3 litellm/setup.py bootstrap` y recrear el contenedor auditor con la
nueva configuración. Ese aprovisionamiento no consulta al modelo; reejecutar
la auditoría sí puede consumir API.

La suite del código actual contiene 16 pruebas originales del harness, 16 de
consolidación/ciclo de vida y 2 de integración. Usa mocks y HTTP en loopback;
la prueba integral puede ejecutar los scanners de patrones reales con un juez
simulado. Para esta actualización documental no se ejecutó ninguna auditoría
contra un proveedor.

Comandos de pruebas sin red externa y de arranque están en [README.md](README.md).
El Draw.io puede abrirse en diagrams.net o en una aplicación compatible: sus
formas, conectores y textos son editables y no requiere imágenes externas.
