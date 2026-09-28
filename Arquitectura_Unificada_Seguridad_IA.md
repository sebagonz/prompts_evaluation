# Arquitectura unificada de seguridad IA: `ai-scan` + análisis de prompts

## 1. Decisión y propósito

Se propone evolucionar hacia un **orquestador único de seguridad IA a nivel
repositorio**, ejecutado en un contenedor OCI interno y consumido desde GitLab
CI. No se reemplazan los análisis existentes: se combinan según el tipo de
activo que inspeccionan y se normalizan sus hallazgos para GitLab y SonarQube.

La propuesta integra dos fuentes locales evaluadas:

| Fuente | Aporte principal | Estado observado |
|---|---|---|
| POC actual (`PromptSonar` + `prompt-injection-auditor`) | Análisis especializado del contenido de prompts `.txt` y `.md`; JSON, un SARIF consolidado y resumen JSON | Ejecutable dentro de la imagen Docker actual; hay definición de pipeline GitLab y job Sonar, pero aún requieren validación end-to-end con la imagen homologada del banco. |
| Diseño `renato` / `ai-scan` | Descubrimiento de componentes IA, prompts construidos en código, dependencias Python, secretos IA, PII de prueba y salidas GitLab | Diseño/prototipo: los módulos se entregaron como fragmentos `.txt`, no como paquete ejecutable. |

El objetivo no es que un único motor sustituya a todos los demás. El objetivo
es que el pipeline tenga **una única decisión de política**, una vista
consolidada para SonarQube y evidencia detallada por motor para investigación.

## 2. Comparación: solapamientos y complementariedad

| Dominio | POC de prompts | `renato` / `ai-scan` | Decisión de unificación |
|---|---|---|---|
| Archivos de prompt externos | PromptSonar y pi-auditor analizan `.txt`/`.md` y evalúan inyección, jailbreak, obfuscación, secretos/PII, aislamiento, jerarquía de instrucciones y hardening. | No los analiza; sólo mira construcción de prompts dentro de código fuente. | Mantener ambos motores del POC como la capa especializada de **prompt assets**. |
| Prompts construidos en código | No es su cobertura actual. | PR-001 busca input no confiable en prompts system/developer; PR-002 identifica prompts extensos hardcodeados. | Incorporar los controles `PR-*` como capa de **templates en código**. Sustituir gradualmente regex por AST/flujo de datos donde sea viable. |
| Componentes IA, MCP y tools | No cubierto. | Detecta SDKs, MCP y potenciales tools con efectos laterales. | Incorporarlo como inventario y priorización de riesgo. No debe por sí solo concluir que un tool es explotable. |
| Secretos y PII | PromptSonar puede señalarlos en un prompt; no es un secret scanner de repositorio. | Busca claves de proveedores IA y PII argentina en datos de prueba. | Usar `ai-scan` como señal de dominio, y conservar GitLab Secret Detection/Gitleaks como control corporativo principal. Evitar duplicados en la vista consolidada. |
| Dependencias | No cubierto. | Reglas para `requirements*.txt`: pinning, hashes, índices y denylist. | Incorporar como chequeo de higiene. Complementar con herramientas de CVE/SBOM aprobadas; las regex no son auditoría de vulnerabilidades. |
| GitLab | Ya existe una definición de job de escaneo y publicación Sonar, no validada integralmente en el banco. | Diseña reportes Code Quality y SAST de GitLab. | Reutilizar la pipeline como punto de partida y validar los contratos GitLab antes de anunciar compatibilidad con sus dashboards. |
| SonarQube | Produce un SARIF 2.1.0 consolidado de ambos motores de prompt. | No produce SARIF. | Normalizar todos los hallazgos propios a **un único SARIF 2.1.0** y validar antes rutas relativas y ubicaciones físicas importables. |
| LLM | No usa LLM. | No usa LLM. | Mantenerlo fuera de la fase inicial; agregarlo luego como etapa opcional, local o aprobada, con datos minimizados. |

### Solapamientos que requieren deduplicación

1. Un secreto en un prompt puede aparecer desde PromptSonar y desde el
   detector `SEC-001`; la fuente de verdad para secretos de repositorio debe
   ser Secret Detection/Gitleaks. El agregador conserva las otras señales como
   contexto, no como vulnerabilidades independientes si comparten ubicación y
   clase.
2. PII dentro de ejemplos de prompts puede ser informada por PromptSonar y por
   `PII-*`. Se necesita una huella determinística basada en archivo, rango,
   regla/familia y contenido redactado, nunca en el dato completo.
3. PR-001 (interpolación) y un finding de robustez del texto pueden coexistir:
   no son duplicados, porque uno trata el **canal de construcción** y el otro
   el **contenido**. Deben mantenerse como hallazgos distintos.

## 3. Arquitectura objetivo

```text
Repositorio / Merge Request
             |
             v
   [1. Recolector y clasificador]
   - diff contra base de MR o full scan de baseline
   - código, manifiestos, prompts, datos de prueba
             |
   +---------+-----------------------------+
   |                                       |
   v                                       v
[2A. Controles de repositorio]       [2B. Controles de prompt]
 ai-scan modularizado                  PromptSonar
 - SDK IA / MCP / tools                prompt-injection-auditor
 - PR-001 / PR-002                     (archivos de prompt)
 - dependencias, secretos, PII
   |                                       |
   +------------------+--------------------+
                      v
          [3. Normalizador y política]
          - modelo canónico de finding
          - huellas, deduplicación y severidad
          - waivers aprobados con vencimiento
          - warn/enforce y umbrales por regla/rama
                      |
          +-----------+------------+----------------+
          v                        v                v
  JSON crudo por motor    SARIF único 2.1.0   GitLab SAST / Code Quality
  + resumen de ejecución        |                    |
                               SonarQube        MR / Security Dashboard

Capas corporativas independientes: GitLab SAST y Secret Detection/Gitleaks.
Etapa futura opcional: evaluador LLM local/aprobado, después de sanitización.
```

### 3.1. Componentes seleccionados y justificación

| Componente | Selección | Justificación |
|---|---|---|
| Orquestador Python | Nuevo paquete `ai_security_scan` | Unifica descubrimiento, rutas, política y formatos. Python ya está presente en el POC y en el diseño `renato`; no debe duplicar los motores externos. |
| `ai-scan` de `renato` | Reutilizar y completar | Cubre riesgos de repositorio que los scanners de prompts no ven. Debe convertirse primero en paquete probado. |
| PromptSonar | Mantener | Aporta análisis estático especializado de texto de prompts, además de salida SARIF nativa. |
| prompt-injection-auditor | Mantener | Aporta checks complementarios de jerarquía, non-disclosure, authority spoofing, delimitación y confirm gates. |
| Normalizador SARIF | Extender el conversor/merger actual | Ya existe una consolidación para dos motores. Se debe ampliar para `ai-scan`, con identificadores estables por herramienta y regla. |
| GitLab SAST y Secret Detection | Mantener como capas nativas | Son controles de plataforma con gestión corporativa; no se sustituyen por regex propias. |
| LLM evaluador | Diferir | No es necesario para validar la arquitectura estática. Su incorporación requiere modelo aprobado, política de datos, evaluación y trazabilidad. |

### 3.2. Rutas de análisis

El clasificador no debe asumir que todo archivo de un repositorio contiene IA.
La ruta se define por extensión, ubicación y contexto de componentes:

| Activo | Motores | Regla de alcance inicial |
|---|---|---|
| Código fuente | `ai-scan` | Python es la cobertura prioritaria del prototipo. JS/TS y notebooks son cobertura parcial hasta incorporar parsers/fixtures: los patrones actuales privilegian imports Python y los detectores de prompts/secretos no inspeccionan notebooks. |
| `requirements*.txt` y, en una evolución, lockfiles/manifiestos Node/Python | `ai-scan` + control corporativo de CVE | Supply chain y configuración. |
| Prompts externos `.txt`, `.md` y extensiones configurables | PromptSonar + pi-auditor | Texto del prompt, no su ejecución con un modelo. |
| Datos de prueba configurados | `ai-scan` PII | Búsqueda contextual, con redacción obligatoria en salidas. |
| Todo el repositorio | GitLab SAST + Secret Detection | Controles transversales gestionados por la plataforma. |

El análisis diff-aware es adecuado para merge requests, pero debe aplicar de
verdad el conjunto de archivos cambiado a todos los detectores. En la rama
principal se ejecuta full scan para obtener baseline y detectar degradaciones.

## 4. Contrato de findings y reportes

Cada motor debe entregar o ser adaptado a este modelo mínimo antes de decidir
la política:

```json
{
  "tool": "promptsonar | pi-auditor | ai-scan",
  "rule_id": "identificador estable",
  "severity": "critical | high | medium | low | info",
  "message": "descripción sin datos sensibles",
  "location": {"path": "ruta/relativa", "start_line": 1},
  "fingerprint": "hash estable",
  "remediation": "acción concreta",
  "standards": ["referencias aplicables"],
  "evidence_redacted": "opcional"
}
```

La severidad canónica es `critical | high | medium | low | info`. El mapeo es
obligatorio y versionado: `ai-scan:blocker -> critical`; PromptSonar y
pi-auditor conservan su severidad de origen como metadato. SARIF usa los
niveles `error`, `warning` y `note`; GitLab y Sonar reciben el mapeo definido
por el normalizador. La política compara siempre la severidad canónica, nunca
los vocabularios de cada herramienta.

La huella debe versionarse y calcularse con, como mínimo,
`version_de_regla + tool + rule_id + ruta_relativa + línea_normalizada +
familia_de_evidencia_redactada`, usando SHA-256. El contrato debe definir cómo
se comporta ante cambios de línea para evitar que findings persistentes se
reabran artificialmente.

Salidas objetivo por job:

| Salida | Nombre propuesto | Consumidor |
|---|---|---|
| Evidencia cruda por motor | `reports/raw/<tool>/...json` | Investigación y recalibración; artefacto con acceso restringido. |
| Resumen de ejecución | `reports/ai-security-scan-summary.json` | CI, métricas y diagnóstico de errores. |
| Hallazgos canónicos | `reports/ai-security-scan-findings.json` | Trazabilidad interna y deduplicación. |
| SARIF único | `reports/ai-security-scan.sarif` | Importación a SonarQube mediante `sonar.sarifReportPaths`. |
| GitLab Code Quality/SAST | `reports/gl-code-quality-report.json`, `reports/gl-sast-report.json` | Widgets y Security Dashboard de GitLab, según licencia/configuración. |

Durante la migración el POC conserva sus contratos ya usados:
`reports/prompt-security-scan.sarif` y
`reports/prompt-security-scan-summary.json`. El job unificado puede crear los
nombres `ai-security-*` sólo cuando incorpore controles de repositorio; no se
debe cambiar una ruta consumida por Sonar sin actualizar el pipeline en la
misma entrega.

El SARIF debe contener una sola raíz y puede incluir varios `runs`, uno por
herramienta. Los JSON crudos **no** son equivalentes al SARIF y no deben
publicarse como si fuesen un informe Sonar.

### 4.1. Preflight obligatorio de SARIF

Antes del job de Sonar, un validador debe rechazar o separar como
“no-publicable” cada resultado sin una ubicación física importable. Por cada
resultado verifica: URI relativa al checkout, archivo existente bajo
`sonar.projectBaseDir`, `startLine >= 1`, codificación UTF-8 y una regla
declarada por el `run` correspondiente. El resumen debe informar totales
generados, ubicados, publicados y omitidos por motivo.

Este requisito corrige dos riesgos del POC actual: PromptSonar puede emitir
URIs bajo `/workspace/...`, que no coinciden con el checkout de GitLab, y
pi-auditor puede producir findings sin líneas. Esos findings siguen siendo
evidencia en el JSON/resumen, pero no se deben prometer como issues Sonar hasta
que se les asigne una ubicación válida o se adopte una estrategia aprobada
para hallazgos sin archivo.

Los hallazgos SARIF se gestionan como issues externos de Sonar. Por ello,
deduplicación, waivers, supresiones y política se aplican **antes** de crear el
SARIF; Sonar no es el motor de configuración de reglas ni de excepciones de
estos analizadores externos.

### 4.2. Datos sensibles y publicación de artefactos

Hoy el directorio `reports/` del POC se publica completo y los JSON/SARIF
pueden contener evidencia o fragmentos del prompt. La redacción de evidencia
todavía no está implementada. La arquitectura objetivo separa
`reports/raw/` (evidencia de acceso restringido) de `reports/publish/`
(SARIF y resúmenes redactados), aplica redacción antes de cargar artefactos y
define retención, `artifacts:access` y autorización conforme a la política del
banco. Secretos y PII nunca se serializan completos en ninguna salida.

## 5. Condiciones para hacer ejecutable `renato`

Antes de integrarlo, se requiere completar estos puntos del material actual:

1. Crear el paquete real `aiscan/` (o el nombre definitivo), con
   `__init__.py`, CLI, modelos, detectores, policy y reportes; agregar
   `pyproject.toml`, lockfile y pruebas/fixtures.
2. Corregir el llamado actual de `run_scan(args.repo, changed_files)`: hoy el
   segundo parámetro corresponde a `manifest`, por lo que el modo diff termina
   ejecutando full scan aunque se anuncia como diff.
3. Implementar `--manifest` o quitarlo del README y CI; actualmente la CI lo
   pasa pero el parser no lo acepta.
4. Definir si el gate sólo se activa con componentes IA. El código actual
   ejecuta secretos, prompts y PII aun cuando no se detectó IA, contradiciendo
   el mensaje de “gate no aplica”.
5. Verificar y mejorar detectores JS/TS, vinculación precisa entre un tool y su
   side effect, análisis de lockfiles y falsas detecciones de regex.
6. Agregar SARIF directamente o un adaptador al normalizador común; versionar
   reglas y mapeos de severidad.
7. Incorporar allowlists/waivers auditables, baseline y configuración por
   repositorio sin permitir que un MR reduzca la política.
8. Validar los reportes GitLab contra el esquema oficial aplicable antes de
   depender de Code Quality o Security Dashboard. El fragmento actual de SAST
   no demuestra aún que cumpla todos los metadatos exigidos.

## 6. Ejecución segura y portable en el laboratorio bancario

La unidad de portabilidad es la **imagen OCI Linux**, no el sistema operativo
del host. SUSE/SLES, otra distribución Linux o macOS sólo necesitan un runtime
de contenedores compatible y acceso al registry autorizado. La imagen final
debe contener Node, Python y los motores ya instalados; el job CI no debe
descargar `apt`, `pip`, npm o GitHub durante la ejecución.

Para un entorno restringido:

1. Construir y validar en una zona autorizada; publicar una imagen versionada
   en Harbor interno.
2. Usar mirrors internos/wheelhouse al construir, fijar versiones y hashes de
   dependencias, y fijar el auditor externo a un commit revisado. Para ello el
   Dockerfile debe hacer `clone/fetch` y `checkout` explícito del SHA; el uso
   actual de `git clone --branch` sirve para ramas/tags, pero no garantiza que
   un SHA arbitrario sea resoluble como rama.
3. Proveer certificados corporativos en la imagen de producción y reactivar
   validación TLS. La desactivación actual de TLS es una excepción explícita
   del POC, no un requisito de la arquitectura final.
4. Ejecutar sin egress a Internet, con filesystem de trabajo efímero y mounts
   mínimos; entregar sólo artefactos redactados a sistemas externos.
5. Separar credenciales de SonarQube/GitLab en variables protegidas y nunca
   incluirlas en los reportes ni logs.

## 7. Política y operación de CI

La política debe ser independiente de cada CLI:

| Fase | Comportamiento | Criterio de salida |
|---|---|---|
| 0 — POC | Informativo; conserva los reportes actuales de prompt | Validar cobertura, estabilidad y formato SARIF. |
| 1 — Calibración | `warn`, artefactos y tablero; sin bloquear merge | Métricas de falsos positivos, tiempos y reglas conflictivas. |
| 2 — Enforce acotado | Bloquea reglas críticas/high previamente aceptadas en archivos del MR | Waivers con dueño, motivo y fecha de vencimiento. |
| 3 — Baseline y ampliación | Full scan programado en rama principal; controles adicionales y LLM opcional | Tendencia, SLA de remediación y revisión de riesgos. |

Un job de publicación Sonar debe depender de la generación exitosa del SARIF,
usar la imagen de SonarScanner aprobada por el banco y configurar la ruta del
artefacto. Esa imagen no debe asumirse: Plataforma/SecOps debe indicar su
nombre interno, versión y método de autenticación.

La plantilla entregada dentro de `renato` no es apta para adopción directa en
esta red: usa `python:3.11-slim` y ejecuta `apt-get`/`pip install` durante el
job. Debe reemplazarse por la imagen OCI interna antes de cualquier piloto.

## 8. LLM: etapa posterior y controlada

Un LLM no debe formar parte de la decisión bloqueante inicial. Cuando se
apruebe, se agrega después de los detectores estáticos con estas restricciones:

- modelo local o endpoint formalmente aprobado; sin enviar prompts, código,
  secretos o PII a servicios no autorizados;
- dataset de pruebas sintético y versionado para jailbreak, exfiltración, tool
  abuse y evasiones;
- prompts del evaluador, versión de modelo, parámetros y resultado trazables;
- resultados como señal adicional que requiere calibración antes de bloquear;
- presupuesto de latencia/costo y modo degradado si el servicio no está
  disponible.

## 9. Riesgos abiertos y decisiones necesarias

1. Confirmar qué formato(s) de reporte y qué versión de SonarQube acepta el
   banco, además de la imagen interna de SonarScanner.
2. Confirmar licencia y habilitación de GitLab Security Dashboard/SAST reports.
3. Acordar catálogo inicial de reglas bloqueantes, ownership y SLA; no heredar
   severidades de los tres motores sin calibración.
4. Definir qué extensiones y directorios son prompts/datos de prueba, y qué
   rutas deben excluirse por privacidad o volumen.
5. Evaluar legalmente la retención de artefactos de hallazgos, incluso
   redactados, y el acceso a ellos.
6. Decidir si `ai-scan` se mantendrá como proyecto propio reutilizable o se
   absorberá en este repositorio. En ambos casos su versionado debe ser
   independiente de las reglas de terceros.

## 10. Plan de implementación verificable

1. **Cerrar y reconciliar el POC actual:** normalizar el `TARGET` a ruta
   absoluta —o ejecutar PromptSonar desde el directorio del checkout— para que
   funcione igual en Compose y GitLab; corregir URIs SARIF, medir findings sin
   `location`, validar el preflight y actualizar README/instrucciones/pipeline
   para que describan los reportes y jobs realmente presentes.
2. **Industrializar `ai-scan`:** reconstruir el paquete, corregir los defectos
   indicados en la sección 5 y agregar pruebas de detector, reportes y policy.
3. **Crear el normalizador común:** importar `ai-scan` junto al SARIF ya
   consolidado del POC; probar IDs, severidades, rutas y deduplicación.
4. **Crear imagen OCI interna:** sin instalaciones runtime, con SBOM,
   procedencia, versiones fijadas y prueba en un runner comparable al banco.
5. **Pilotar CI en warn:** GitLab MR y Sonar con artefactos; medir precisión,
   duración y comportamiento con proxy/sin egress.
6. **Aplicar enforcement por etapas:** primero reglas críticas verificadas,
   luego ampliar cobertura y ejecutar baseline programado.

### Criterios de aceptación mínimos

| Fase | Criterio medible |
|---|---|
| POC cerrado | 100% de los resultados publicados en SARIF tienen ruta relativa existente y línea válida; el resumen declara los no-publicables. |
| `ai-scan` industrializado | Pruebas de detectores, policy y formatos pasan; Python es la cobertura prioritaria y JS/TS/notebooks se marcan como parcial hasta tener parsers y fixtures. |
| Imagen interna | Ejecución exitosa sin egress a Internet en un runner de prueba; dependencias, versiones y procedencia registradas. |
| Piloto warn | Tiempo máximo acordado por repositorio, tasa de falsos positivos medida por regla y 100% de reglas con remediación/owner. |
| Enforce | Sólo reglas calibradas; waiver con dueño y vencimiento; ningún MR puede disminuir la política desde su propio código. |

## 11. Evidencia analizada

- POC: `Dockerfile`, `docker-compose.yml`, `scripts/scan-prompts.sh`,
  `scripts/pi_auditor_to_sarif.py`, `scripts/build_scan_summary.py` y
  `scripts/merge_sarif_reports.py`.
- Diseño `renato`: `renato/README.md`, `renato/cli - copia.txt`,
  `renato/ai_components - copia.txt`, `renato/prompts - copia.txt`,
  `renato/dependencies - copia.txt`, `renato/secrets - copia.txt`,
  `renato/pii - copia.txt`, `renato/policy - copia.txt`,
  `renato/report - copia.txt` y `renato/gitlab-ci - copia.txt`.

Este documento es un diseño propuesto. No afirma que `renato`, el pipeline
unificado, los reportes GitLab ni la publicación Sonar estén ya implementados.
