# Contexto para integrar el analizador semántico de prompts

**Proyecto actual:** `giskard-poc`  
**Fecha del estado resumido:** 2026-11-05

## Objetivo y alcance

El analizador revisa **estáticamente** los archivos `prompts/**/*.txt`, destinados a ser prompts de sistema. Busca defectos en sus instrucciones mediante un LLM juez. No ejecuta esos TXT como prompts de sistema de una aplicación ni comprueba herramientas, permisos o comportamiento real. Los hallazgos son propuestas que requieren revisión humana; `NO_FINDINGS` no certifica seguridad.

Solo se incluyen TXT visibles. Los archivos `.md`, ocultos y enlaces simbólicos quedan fuera. Un TXT vacío o que exceda `MAX_INPUT_CHARS` termina en `ERROR`.

## Archivos principales

| Archivo | Función |
| --- | --- |
| `analyzer/semantic_scan_prompts.py` | Harness: selección de TXT, llamadas al juez, validación, concurrencia, reportes y stdout. |
| `analyzer/audit_rubric.md` | Rúbrica con 19 reglas `SEM-*`, títulos, criterios, ejemplos, contraejemplos y correspondencias orientativas a OWASP LLM Top 10 y NIST AI 100-2. Los IDs `SEM-*` son locales. |
| `analyzer/funcionamiento_harness.md` | Explicación detallada del flujo, mensajes al LLM y ciclos del harness. |
| `analyzer/test_scan_prompts.py` | Pruebas locales con respuestas simuladas. |
| `analyzer/Dockerfile` y `docker-compose.yml` | Imagen y servicio `prompt-analyzer`. |
| `reports/prompt_audit/` | Reportes JSON del analizador semántico. |

## Flujo del harness

1. `main()` descubre y ordena los TXT y crea una tarea asíncrona por archivo. `MAX_PARALLEL_PROMPTS` limita las llamadas concurrentes; el valor predeterminado es 4. Cada tarea tiene su propio contexto y sus propios reintentos. El orquestador reúne resultados según terminan y conserva el orden de archivos en el JSON final.
2. Para cada TXT, el mensaje **`system` del juez** contiene la rúbrica y el esquema JSON. El mensaje **`user` del juez** contiene el *prompt de sistema objetivo* numerado y delimitado como dato no confiable. Que el documento vaya en el mensaje `user` del juez **no** cambia su rol previsto en la aplicación auditada.
3. `litellm.acompletion()` llama al alias del proxy LiteLLM mediante su API compatible con OpenAI. `MAX_ATTEMPTS` vale 2 por defecto y cubre respuestas truncadas, JSON inválido o citas inválidas; los errores de conexión se registran como `ERROR` sin ese reintento. Si falla el JSON se vuelve a pedir el reporte completo. Si fallan citas, se pide únicamente la corrección o el retiro explícito de esos hallazgos y se conservan los ya validados. Cada intento adicional puede tener costo.
4. Pydantic valida el esquema. Cada hallazgo debe indicar `rule_id`, `severity`, `title`, `explanation`, `recommendation`, `impact_conditions`, `line_number` y `evidence`. El harness acepta citas literales de la línea indicada, corrige una línea equivocada solo si la misma cita aparece de manera única en otra línea, y admite un tramo único de dos líneas contiguas con `end_line_number`. Marca ajustes en `citation_adjustment` y conserva `model_line_number` cuando corresponde. Citas con patrones reconocidos de claves se rechazan. La validación literal no confirma la interpretación semántica del juez.
5. El orquestador escribe un JSON por archivo y un resumen. Muestra progreso, tiempos UTC y duraciones en stdout, seguido por tablas de hallazgos y una sección final **«Archivos con ERROR»** con archivo y diagnóstico.

## Reportes y códigos de salida

El resumen más reciente está en `reports/prompt_audit/summary.json`. Cada corrida conserva `reports/prompt_audit/runs/<run_id>/summary.json` y un JSON por TXT. El resumen incluye `run_id`, `model`, `rubric_sha256`, tiempos, `counts` y `results`. Cada resultado incluye `file`, `sha256`, `status`, `findings`, fechas y duración; cuando hay error, también `error` y, si corresponde, `partial_findings`. El campo `error` ya contiene un diagnóstico redactado; no se guarda la respuesta cruda del LLM.

| Estado | Significado |
| --- | --- |
| `REVIEW` | Respuesta válida con uno o más hallazgos propuestos. |
| `NO_FINDINGS` | Respuesta válida sin hallazgos propuestos. |
| `ERROR` | Auditoría incompleta o inválida. `findings` queda vacío. Las citas verificables de un intento fallido pueden conservarse en `partial_findings`, separadas y marcadas como parciales. |

El proceso sale con código **2** si hay al menos un `ERROR`; en otro caso, con **1** si hay `REVIEW` y `FAIL_ON_FINDINGS=1`; en los demás casos, con **0**. Los hallazgos parciales no convierten un `ERROR` en `REVIEW` ni deben tratarse como resultado completo. Si un reintento devuelve `findings=[]` después de haberse verificado citas en un intento anterior, el archivo permanece en `ERROR` para evitar un falso `NO_FINDINGS`.

Los hashes `sha256` del TXT y de la rúbrica sirven para trazabilidad. **Todavía no hay lógica que omita automáticamente archivos ya analizados.**

## Ejecución y verificación

En esta prueba local, `prompt-analyzer` usa LiteLLM mediante `LITELLM_BASE_URL`, `LITELLM_API_KEY` y `MODEL_NAME`. Se construye con `docker compose build prompt-analyzer` y se ejecuta con `docker compose run --rm --no-deps prompt-analyzer`. Este último comando **sí llama al LLM configurado y puede generar costos**. Para cambios sencillos se acordó usar pruebas con respuestas simuladas, sin ejecutar el analizador real contra el modelo.

Las últimas modificaciones añadieron al resumen final de stdout los archivos con `ERROR` y sus diagnósticos, un reintento dirigido a citas rechazadas, reparación determinista limitada y contraejemplos más precisos en la rúbrica. Pasaron **16 pruebas simuladas** en Docker sin red. No se realizó una corrida real contra el LLM después de estos cambios; los JSON existentes pueden corresponder a versiones anteriores del código.

## Integración en `prompts-analizer` (5 de noviembre de 2026)

La integración está implementada. Los archivos activos están en `scripts/` y
la imagen única se construye con `Dockerfile`, usando
`requirements-semantic.txt`. `scripts/test_scan_prompts.py` conserva los tests
del proyecto original; se agregaron pruebas de integración y consolidación.

El semántico se ejecuta separado mediante `semantic-scan`, que apunta al
harness. Este registra en su propio resumen el estado de la corrida y el código
de salida, incluso ante fallas de arranque. Reemplaza el resumen anterior al
iniciar; el consolidador rechaza corridas incompletas o interrumpidas. No hay
wrapper ni recibo semántico adicional.
`consolidate_scan_reports.py` recibe los artefactos de los tres scanners,
valida cobertura/hashes y produce resumen/stdout/SARIF conjuntos, con un run
por herramienta. Conserva trazabilidad, rangos y ajustes de citas. Los errores
son ERROR general y los parciales permanecen fuera del SARIF.

Compose incluye infraestructura y workers independientes con la misma imagen
del analizador; `consolidate` espera a ambos. `scripts/start-local.sh` prepara
el proxy y la clave virtual antes de levantar el conjunto. En CI el semántico
es optativo mediante `RUN_SEMANTIC_SCAN=true`; requiere variables del proxy.

No hay caché de auditorías ni validación dinámica de la aplicación. Las pruebas
de integración usan mocks y red externa deshabilitada. No se corrió el juez real.

La [guía principal](README.md) contiene los comandos vigentes; las rutas
`analyzer/` de las secciones anteriores corresponden al proyecto de origen.
