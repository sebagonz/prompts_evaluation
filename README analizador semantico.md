# Analizador semántico integrado

El código y las pruebas de `giskard-poc` están incorporados en `scripts/`.
La implementación usa la misma imagen que PromptSonar y pi-auditor, con un
proceso y reportes separados. La [guía principal](README.md) describe el
arranque completo, el flujo GitLab, los artefactos y las pruebas sin API.

## Flujo

El harness lee TXT visibles, prepara la rúbrica y el documento numerado como
dato no confiable, llama al alias de LiteLLM y valida la respuesta con
Pydantic y citas literales. No ejecuta el prompt objetivo como aplicación.
La [explicación del harness](scripts/funcionamiento_harness.md) y la
[rúbrica](scripts/audit_rubric.md) detallan reglas, reintentos y limitaciones.

`semantic-scan` apunta directamente a `scripts/semantic_scan_prompts.py`.
El harness reemplaza el resumen anterior antes de validar la configuración y
registra el estado de la corrida en su propio `summary.json`: `RUNNING`,
`COMPLETE`, `ERROR` o `NOT_APPLICABLE`. También guarda `exit_code`; no hay un
script ni recibo de ejecución adicional. Las fallas de arranque se registran
en `error` y una interrupción deja el resumen en `RUNNING`.

`--defer-exit` conserva los errores en ese JSON y termina en cero para permitir
que Compose/GitLab ejecuten la consolidación, que devuelve el código final.
Sin esa opción, el harness devuelve su propio código.

## Uso independiente

Con el proxy ya disponible y `.env` configurado:

```bash
docker compose run --rm --no-deps prompt-analyzer prompts
# O un único archivo:
docker compose run --rm --no-deps prompt-analyzer prompts/vulnerable_prompt.txt
```

Estos comandos sí llaman al modelo configurado y pueden generar gastos.
En el proyecto anterior se usaba `docker compose run --rm --no-deps prompt-analyzer`;
el servicio conserva ese nombre. Aquí su comando por defecto usa
`--defer-exit` para el flujo completo. Pasar `prompts` explícitamente sirve
para recibir el exit code propio al ejecutarlo separado.

Para usar el proxy del cliente, definir `LITELLM_BASE_URL`,
`LITELLM_AUDITOR_KEY` y `AUDIT_MODEL` en el entorno Compose. El SDK recibe
`LITELLM_API_KEY` y `MODEL_NAME`. En GitLab configurar directamente estos dos
últimos nombres y `LITELLM_BASE_URL` como variables CI.

## Contrato y reportes

- `REVIEW`: hallazgos propuestos con citas verificables; requieren revisión humana.
- `NO_FINDINGS`: sin propuestas; no certifica seguridad.
- `ERROR`: análisis incompleto. `findings` queda vacío; `partial_findings` se conserva separado.

El harness escribe `reports/prompt_audit/summary.json`, un resumen por corrida
en `runs/<run_id>/summary.json` y un JSON por TXT. Conserva modelo, hashes de
contenido/rúbrica, tiempos y diagnósticos redactados. stdout muestra tablas y
archivos con errores. No guarda la respuesta cruda del juez.

La consolidación verifica cobertura y hashes, incorpora solo hallazgos completos
y aplica `FAIL_ON` a las tres fuentes. Exporta `end_line_number`,
`citation_adjustment` y `model_line_number` cuando existen. Un error semántico
produce resumen general `ERROR`, código `2` y ningún SARIF final. Los parciales
se consultan en el reporte original y nunca se publican como auditoría completa.

## Configuración

| Variable del harness | Predeterminado |
| --- | --- |
| `MODEL_NAME`, `LITELLM_BASE_URL`, `LITELLM_API_KEY` | Obligatorias |
| `AUDIT_RUBRIC_PATH` | La rúbrica instalada por el Dockerfile unificado |
| `MAX_ATTEMPTS` | `2` |
| `MAX_PARALLEL_PROMPTS` | `4` |
| `MAX_OUTPUT_TOKENS` | `6000` |
| `MAX_INPUT_CHARS` | `30000` |
| `REQUEST_TIMEOUT_SECONDS` | `120` |
| `USE_JSON_SCHEMA` | `1` |
| `FORCE_COLOR` / `NO_COLOR` | Control de colores en stdout |

Los reintentos pueden consumir API. El wrapper fija `FAIL_ON_FINDINGS=0`:
el bloqueo común se calcula al consolidar; los errores siguen siendo `2`.
Markdown no participa del análisis semántico; una selección sin TXT se informa
como `NOT_APPLICABLE`. El harness también permite seleccionar un TXT puntual.

## Pruebas

`scripts/test_scan_prompts.py` conserva las pruebas originales del otro
proyecto. `scripts/test_consolidate_scan_reports.py` agrega pruebas de los
contratos de integración. Ejecutar con `--network none` según el README:
solo respuestas simuladas y HTTP en loopback, sin proveedores externos.
