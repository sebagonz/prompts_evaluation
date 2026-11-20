# Categorías de PromptSonar en este proyecto

Este proyecto usa `@promptsonar/cli` **1.5.1** (fijado en `package.json`). En
esa versión, cada finding de PromptSonar tiene una `category` y una `severity`.
Son campos distintos: la categoría indica **qué aspecto del prompt se evaluó**;
la severidad indica **cuán prioritario es el hallazgo**. El JSON también incluye
`pillar_scores`, con una puntuación para cada una de las siete categorías. Una
puntuación puede aparecer aunque no haya findings de esa categoría.

Los identificadores de la tabla son los valores exactos de `findings[].category`
en el motor instalado en la imagen. Los IDs de reglas son ejemplos, no el
catálogo completo.

| Categoría | Qué revisa | Ejemplos de reglas | ¿Entra al SARIF final por defecto? |
| --- | --- | --- | --- |
| `security` | Inyección, evasión, secretos/PII, RAG, acceso privilegiado y escalamiento de flujos. | `sec_rag_injection`, `sec_owasp_llm02_pii`, `sec_privileged_sink_access` | Sí, si cumple `FAIL_ON` y no está exceptuada. |
| `clarity` | Instrucciones vagas, abiertas o sin límites cuantificados. | `clarity_vague_words`, `clarity_missing_quantifier` | No. |
| `structure` | Contratos y restricciones de formato de salida. | `struct_missing_format_enforcer` | No. |
| `best_practices` | Rol, ejemplos y criterios de verificación del prompt. | `bp_missing_persona`, `bp_missing_few_shot`, `bp_missing_cot` | No. |
| `consistency` | Instrucciones que se contradicen entre sí. | `consist_contradiction` | No. |
| `efficiency` | Presupuesto de tokens, longitud y potencial de compresión. | `eff_token_budget`, `eff_compression_potential` | No. |
| `ethics` | Señales de sesgo o formulaciones manipulativas. | `ethics_bias_indicator`, `ethics_manipulation` | No. |

## Cómo se usan aquí

`scan-prompts.sh` ejecuta PromptSonar y conserva **todos** sus findings en el
JSON por prompt (`reports/*-promptsonar.json`). PromptSonar 1.5.1 no ofrece una
opción `--categories` en `scan --help`. La variable
`PROMPTSONAR_SONAR_CATEGORIES` pertenece a **este proyecto**: el consolidado
lee su lista, filtra el SARIF de PromptSonar y decide qué findings de ese
analizador cuentan para el scan gate. El valor predeterminado es `security`.

Para que un finding de PromptSonar entre al SARIF final deben cumplirse **las
tres condiciones**:

1. Su `category` está en `PROMPTSONAR_SONAR_CATEGORIES`.
2. No tiene una excepción vigente (`waived: true` en el JSON).
3. Su `severity` alcanza el umbral único `FAIL_ON`.

`FAIL_ON` vale `critical` por defecto. `FAIL_ON=medium` incluye y bloquea
`medium`, `high` y `critical`; `FAIL_ON=none` publica todas las severidades
elegibles sin bloquear por severidad. Elegir una categoría **no** reduce el
umbral: por ejemplo, `structure` con severidad `medium` sigue excluida si
`FAIL_ON=critical`.

El filtro de categorías **no se aplica a PI-AUDITOR**; sus hallazgos pasan por
el mismo umbral de severidad `FAIL_ON`. `EXIT_ON_FINDINGS=false` permite que el
job termine en `0` aunque el resumen registre `BLOCK`; no cambia qué se envía
en el SARIF. SonarQube aplica luego su propio quality gate al importar el
archivo.

El resumen de stdout muestra por prompt qué findings se envían a Sonar y
cuáles se excluyen, con el motivo. El JSON original conserva los excluidos y
el SARIF final queda en `reports/prompt-security-scan.sarif`. La selección de
categorías no vuelve a calcular `pillar_scores` ni `overall_score` del JSON.

## Configuración local

Para incluir seguridad y estructura desde severidad media:

```bash
PROMPTSONAR_SONAR_CATEGORIES=security,structure FAIL_ON=medium \
  LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" \
  docker compose run --rm prompt-security prompts/hardest_prompt.txt
```

Con ese prompt de ejemplo, `struct_missing_format_enforcer` pasa a ser
elegible y `PI-NO-ROLEGUARD` también se publica por ser `medium`. El finding
`sec_rag_injection` permanece excluido por su excepción específica.

Para habilitar las siete categorías, se deben enumerar explícitamente:

```bash
PROMPTSONAR_SONAR_CATEGORIES=security,clarity,structure,best_practices,consistency,efficiency,ethics \
  FAIL_ON=medium docker compose run --rm prompt-security prompts
```

En GitLab se puede definir `PROMPTSONAR_SONAR_CATEGORIES` como variable del
job `prompt_security_scan` o como variable CI del proyecto. Se pasa como CSV
sin espacios obligatorios, por ejemplo `security,structure`. El consolidado
acepta mayúsculas en la configuración y rechaza categorías desconocidas con
código `2`, para que un error tipográfico no elimine findings sin avisar.

## Cómo revisar un resultado

En `reports/*-promptsonar.json`, revisar `findings[].category`,
`findings[].severity` y `findings[].waived`. `pillar_scores` resume las siete
áreas, pero **no** es la lista de hallazgos enviados a Sonar. Para saber qué
se envía, usar las filas `SE ENVIAN A SONAR` del resumen de stdout o abrir
`reports/prompt-security-scan.sarif`.

La lista de categorías y los ejemplos de reglas se verificaron contra la imagen
local, que tiene `@promptsonar/cli` **1.5.1** y `@promptsonar/core` **1.5.1**.
El paquete CLI declara dependencia `^1.5.1` de core y este repositorio no tiene
`package-lock.json`; conviene volver a verificar la taxonomía al reconstruir
la imagen o actualizar la dependencia.
Como referencia general, consultar el [repositorio oficial de PromptSonar](https://github.com/meghal86/promptsonar)
y su [catálogo de reglas](https://github.com/meghal86/promptsonar/blob/main/docs/rules.md).
El contenido de la rama `main` puede cambiar; para esta integración prevalece
la versión instalada en la imagen.
