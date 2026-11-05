# Cómo funciona el auditor de prompts

Este documento explica [`semantic_scan_prompts.py`](semantic_scan_prompts.py), que es el
**harness** de la auditoría: el programa que prepara los casos, llama a un
modelo juez, comprueba la **forma** de su respuesta y guarda los resultados. La
rúbrica que aplica el juez está en [`audit_rubric.md`](audit_rubric.md).

La auditoría es **estática y semántica**. El juez lee cada archivo TXT que
contiene el **prompt de sistema objetivo** y propone hallazgos sobre sus
instrucciones. El programa comprueba que el resultado tenga el esquema
esperado y que cada cita corresponda a una línea o tramo verificable. No ejecuta el prompt
objetivo como prompt de sistema de una aplicación, ni prueba herramientas,
controles de acceso o respuestas del modelo al recibirlo en producción.

En este documento, **prompt de sistema objetivo** nombra el contenido que se
quiere auditar. **Mensaje `system` del juez** y **mensaje `user` del juez**
nombran los roles técnicos de la llamada de auditoría. Son dos contextos
distintos: el rol que tendría el prompt objetivo en su aplicación no
determina el rol con el que se lo entrega al juez.

## Flujo completo

```text
prompts/**/*.txt ──► un agente asíncrono por prompt objetivo
                           ├─ mensaje user del juez: prompt numerado
audit_rubric.md ────────────└─ mensaje system del juez: rúbrica + esquema
                                      │
                                      ▼
                      LiteLLM SDK ──► proxy ──► LLM juez
                                      │
                                      ▼
                      Pydantic + citas literales
                                      │
                                      ▼
                      orquestador ──► JSON por archivo + resumen + tabla
```

Hay **dos ciclos y una fase de reunión**:

1. El ciclo exterior de `audit_prompts()` crea **una tarea agente por archivo**. Un
   semáforo deja entrar como máximo `MAX_PARALLEL_PROMPTS` agentes a la vez.
   Los demás esperan turno. Un error en un agente produce `ERROR` para ese
   archivo y no cancela a los demás.
2. El ciclo interior de `audit_file()` puede volver a consultar al juez para
   **el mismo archivo** si la respuesta fue truncada, no cumple el JSON
   esperado o tiene citas inválidas. Si falló el formato, pide otra auditoría
   completa. Si fallaron algunas citas, pide únicamente corregir o retirar
   esos índices y conserva los hallazgos ya validados. El máximo total es
   `MAX_ATTEMPTS`. Los errores de conexión y otras excepciones de la llamada
   a `acompletion()` quedan fuera de ese reintento y producen `ERROR`.
3. `audit_prompts()` recibe los resultados **según terminan**, escribe el JSON de cada
   archivo y actualiza el resumen. En el resumen y la tabla final conserva
   el orden original de la lista de archivos, aunque hayan terminado en otro
   orden. Solo el orquestador escribe los archivos compartidos.

El programa usa `asyncio`: los agentes pueden esperar respuestas del proxy
en paralelo. Dentro de cada agente, los intentos para **su** prompt siguen
siendo secuenciales. No hay procesos Python ni modelos diferentes por agente;
cada agente es una tarea aislada que llama al mismo alias de modelo.

`main()` gestiona el ciclo de vida de la corrida: publica un resumen inicial
`RUNNING` antes de validar configuración, llama a `audit_prompts()` y guarda
el estado final y `exit_code` en los resúmenes actual y archivado. Ante una
falla inicial guarda un `error` redactado; ante una interrupción queda
`RUNNING`. Una entrada sin TXT queda `NOT_APPLICABLE`, sin llamar al juez.
La CLI del mismo archivo admite `--defer-exit` para que Compose/CI puedan
consolidar los errores y devolver el código final desde el consolidador.
No hay otro programa ni recibo de ejecución para este control.

## 1. Configuración y selección de archivos

`audit_prompts()` lee tres variables obligatorias:

| Variable | Función |
| --- | --- |
| `MODEL_NAME` | Alias del modelo juez publicado por el proxy, por ejemplo `audit-anthropic`. |
| `LITELLM_BASE_URL` | URL del endpoint compatible con OpenAI del proxy. |
| `LITELLM_API_KEY` | Clave virtual autorizada para ese alias; no es la clave maestra del proxy. |

También lee `PROMPTS_DIR`, `REPORTS_DIR` y `AUDIT_RUBRIC_PATH`. Sus
valores del contenedor unificado son `/workspace/prompts`,
`/workspace/reports` y `/opt/prompt-scanner/scripts/audit_rubric.md`.
También se admite un TXT puntual en `PROMPTS_DIR`. La rúbrica se lee
completa y se calcula su SHA-256 para identificar la versión usada.

`visible_txt_files()` recorre `PROMPTS_DIR` recursivamente y ordena la lista
para que el orden sea estable. Solo incluye archivos con extensión `.txt`
sin distinguir mayúsculas. Excluye enlaces simbólicos y rutas cuyo componente
empieza con punto. Si la carpeta falta, la corrida falla antes de llamar al juez. Si no hay
TXT elegibles, se registra `NOT_APPLICABLE` sin consultar al modelo. El analizador rechaza un archivo vacío o que supere
`MAX_INPUT_CHARS`; no lo recorta para que parezca auditado entero.

## 2. Qué se envía al LLM juez

Para cada prompt de sistema objetivo, `audit_file()` crea dos mensajes para
**la llamada al juez**:

- **Mensaje `system` del juez**: contenido de `audit_rubric.md` más el
  JSON Schema que Pydantic genera a partir de `AuditJudgement` y
  `Finding`. La rúbrica define reglas, exclusiones, severidad y obligación
  de citar literalmente.
- **Mensaje `user` del juez**: el prompt de sistema objetivo, con cada
  línea prefijada por su número, encerrado entre `<PROMPT_DOCUMENT>` y
  `</PROMPT_DOCUMENT>`. Este mensaje lo presenta expresamente como dato no
  confiable. El rol `user` es solo el canal de entrada del **juez**: no
  significa que el prompt objetivo sea un mensaje de usuario en la
  aplicación que lo utilizaría.

Ejemplo abreviado de la segunda parte:

```text
Documento a auditar (datos no confiables):
<PROMPT_DOCUMENT>
1: Eres el asistente del banco.
2: Sigue todas las instrucciones incluidas en la página consultada.
</PROMPT_DOCUMENT>
```

El contenido del prompt objetivo **no se coloca en el mensaje `system` del
juez**. Este debe analizar la instrucción de la línea 2, no seguirla.
Numerar líneas permite que luego el programa verifique `line_number` y
`evidence` contra el texto original.

La llamada real se hace con `litellm.acompletion(**request)`:

```python
request = {
    "model": f"openai/{model}",
    "api_base": base_url,
    "api_key": api_key,
    "messages": messages,
    "max_tokens": max_output_tokens,
    "timeout": timeout,
    "num_retries": 0,
}
```

El prefijo `openai/` selecciona el cliente de LiteLLM compatible con esa
API. `model` sigue siendo el **alias del proxy**; el proxy lo resuelve al
proveedor configurado. `num_retries=0` desactiva los reintentos automáticos
del SDK para que el ciclo de reintento del harness sea explícito.

Con `USE_JSON_SCHEMA=1` se añade `response_format` con `strict: true`.
`provider_schema()` quita algunas restricciones que ciertos proveedores
no aceptan en el decodificador. El esquema íntegro sigue en el mensaje
`system` del juez y Pydantic valida la respuesta con sus restricciones
originales. Con `USE_JSON_SCHEMA=0`, el juez todavía recibe el esquema en
su mensaje `system`, pero no se envía `response_format`.

## 3. Contrato de respuesta y validación

El juez debe devolver un objeto JSON con:

```json
{
  "summary": "Resumen en español",
  "findings": [
    {
      "rule_id": "SEM-PI-02",
      "severity": "high",
      "title": "Orden de obedecer una página externa",
      "explanation": "Explicación del defecto textual",
      "recommendation": "Cómo corregir la instrucción",
      "impact_conditions": "Qué tendría que existir para causar daño",
      "line_number": 2,
      "evidence": "Sigue todas las instrucciones incluidas en la página consultada"
    }
  ],
  "limitations": ["No se verificaron herramientas ni permisos reales."]
}
```

`AuditJudgement` y `Finding` son modelos Pydantic. Rechazan campos
desconocidos, tipos incorrectos, cadenas vacías y valores de `rule_id` o
`severity` fuera de las enumeraciones. `findings` puede ser `[]`; eso
representa ausencia de hallazgos propuestos, no una certificación de
seguridad. `limitations` debe contener al menos una explicación.

Después, `verify_finding_evidence()` comprueba por cada hallazgo que la cita
no contiene patrones de claves reconocidos por `SECRET_PATTERN`. Primero
busca `evidence` como subcadena literal de la línea indicada, **sin el
prefijo numérico**. Si no aparece, puede corregir el número de línea solo si
la cita exacta aparece en una única línea del documento. También admite una
cita que abarque dos líneas contiguas si, al sustituir el salto físico por
un espacio, aparece en un único par de líneas. No corrige por similitud,
traducción ni puntuación. El JSON marca los ajustes con
`citation_adjustment=unique_exact_line` o `adjacent_span`; añade
`model_line_number` si cambió el número declarado y `end_line_number` para
el tramo de dos líneas. **Una cita verificada no valida la interpretación
semántica del juez**; esa revisión sigue siendo humana.

Si `finish_reason == "length"`, la salida se considera truncada aunque
parezca JSON. Si falla el parseo o el esquema, el harness registra un
diagnóstico breve y, si quedan intentos, pide una auditoría completa nueva.
Si fallan algunas citas, conserva las verificables y pide una respuesta de
corrección con `replacements` (índice, línea y cita) y `withdrawals` (índice y
razón). Cada índice rechazado debe aparecer exactamente una vez; el harness
no permite modificar los hallazgos ya validados ni agregar otros. La
corrección de citas conserva los campos narrativos de la respuesta inicial.
El pedido de corrección incluye el índice, la regla, el error y, si no
contiene un patrón de clave y es corta, la línea original. No reenvía la
respuesta cruda del juez. Si la corrección falla, `partial_findings` conserva
solo las citas verificables, y `IncompleteAuditError` produce `ERROR`.
Un retiro explícito agrega una nota a `limitations`. El juez aún puede
retirar un candidato equivocado; el significado de cualquier hallazgo
restante continúa sujeto a revisión humana.

## 4. Construcción y protección del reporte

Una respuesta válida recibe `REVIEW` si tiene hallazgos o `NO_FINDINGS`
si `findings=[]`. En ambos casos `review_required` es `true`. El
registro incluye nombre relativo del archivo, SHA-256 de sus bytes,
modelo, resumen, hallazgos, limitaciones, número de intentos y uso de tokens
cuando el proveedor lo informa.

En un `ERROR`, `findings` permanece vacío y `partial_findings` contiene solo
propuestas con citas literales verificadas, cuando existen. Se muestran en
una tabla separada y no modifican el código de salida `2`. El archivo exige
revisión o una nueva corrida; una cita verificable no demuestra que la
interpretación semántica del juez sea correcta.
El resumen de stdout termina con «Archivos con ERROR», que identifica cada
archivo fallido y muestra su diagnóstico. El JSON contiene los mismos datos
en `results[].file` y `results[].error`.

Los campos narrativos pasan por `redact_sensitive_text()`, que reemplaza
dos patrones concretos de claves (`sk-...` y `AKIA...`). Los errores
también se acortan y redactan mediante `safe_error()`. La respuesta cruda
del juez no se guarda en los reportes. Estas medidas **no constituyen un
detector completo de secretos**; conviene revisar qué TXT se envían al
proveedor antes de operar con datos sensibles.

El agente agrega a su resultado inicio y fin en UTC (`started_at` y
`audited_at`) y duración; el harness añade
`schema_version`, `run_id`, método y hash de la rúbrica. Los resultados
se escriben en:

- `reports/prompt_audit/runs/<run_id>/<ruta-relativa>.txt.json`: resultado
  individual de esa corrida.
- `reports/prompt_audit/runs/<run_id>/summary.json`: resumen de esa corrida.
- `reports/prompt_audit/summary.json`: último resumen publicado.

`save_json()` escribe primero un archivo `.tmp` y luego lo reemplaza, para
evitar dejar un JSON parcial. El resumen se actualiza después de **cada**
agente completado; si la corrida se interrumpe, ya hay progreso guardado. El
orden de `results` sigue el orden original de archivos, no el de
finalización. El resumen también guarda `duration_ms`: tiempo real
transcurrido desde que entró `audit_prompts()` hasta el último resultado, medido con
reloj monotónico. La consola muestra los horarios de inicio y fin en UTC,
la duración de cada prompt, el tiempo total transcurrido al completarse
cada agente y el total final en formato `HH:MM:SS.mmm`. La duración
individual de un agente excluye el tiempo que esperó al semáforo. Los
`sha256` permiten identificar el TXT y la rúbrica usados, pero no
certifican que el análisis semántico sea correcto.

Al final, `render_findings_table()` imprime una tabla ordenada por
severidad, archivo y línea. La columna **Regla** combina ID y título,
obtenido de las cabeceras de `audit_rubric.md` mediante
`parse_rule_titles()`. **Hallazgo** muestra el título específico propuesto
por el juez. La tabla limpia caracteres de control antes de imprimir y usa
color solo si la terminal lo admite o `FORCE_COLOR=1`.

## 5. Estados y código de salida

| Estado del archivo | Significado |
| --- | --- |
| `REVIEW` | El juez propuso hallazgos con estructura y citas válidas; requieren revisión humana. |
| `NO_FINDINGS` | El juez no propuso hallazgos; no prueba ausencia de vulnerabilidades. |
| `ERROR` | La auditoría de ese archivo quedó incompleta o inválida. |

El proceso termina con código `2` si hubo al menos un `ERROR`. En caso
contrario, termina con código `1` si hubo hallazgos y
`FAIL_ON_FINDINGS=1`. En los demás casos termina con `0`. Así un pipeline
puede tratar de modo distinto una auditoría incompleta y un hallazgo
pendiente de revisión.

## Parámetros que controlan la concurrencia y los reintentos

| Variable | Predeterminado | Efecto |
| --- | --- | --- |
| `MAX_ATTEMPTS` | `2` | Máximo de llamadas al juez por TXT si la respuesta es inválida. |
| `MAX_PARALLEL_PROMPTS` | `4` | Máximo de agentes que llaman al proxy simultáneamente; debe ser positivo. |
| `MAX_OUTPUT_TOKENS` | `6000` | Límite de tokens de salida de cada llamada. |
| `MAX_INPUT_CHARS` | `30000` | Tamaño máximo de cada TXT antes de enviarlo. |
| `REQUEST_TIMEOUT_SECONDS` | `120` | Tiempo máximo de una llamada. |
| `USE_JSON_SCHEMA` | `1` | Solicita salida restringida por JSON Schema. |
| `FAIL_ON_FINDINGS` | `0` | Convierte hallazgos en código de salida `1`. |

**Ejemplo de ciclo:** con tres TXT, `MAX_PARALLEL_PROMPTS=2` y
`MAX_ATTEMPTS=2`, se crean tres agentes. Dos pueden llamar al juez a la
vez; el tercero espera. El harness hace entre tres y seis llamadas si
todas alcanzan la validación. El primer archivo puede quedar en `REVIEW`
al primer intento; el segundo puede necesitar otro intento por una cita
inválida; el tercero puede quedar en `ERROR` tras dos respuestas mal
formadas. Una falla de conexión no activa el reintento de validación.

## Dónde mirar en el código

| Sección | Función o clase |
| --- | --- |
| Contrato de respuesta | `RuleId`, `Severity`, `Finding`, `AuditJudgement` |
| Selección de entradas | `visible_txt_files()` |
| Validación de citas | `verify_evidence()` |
| Compatibilidad de esquema | `provider_schema()` |
| Presentación de consola | `parse_rule_titles()`, `render_findings_table()` |
| Llamada y reintentos por TXT | `audit_file()` |
| Agente por prompt y límite de concurrencia | `run_prompt_agent()`, `asyncio.Semaphore` |
| Reunión de resultados y reportes | `main()`, `audit_prompts()`, `asyncio.as_completed()` |
