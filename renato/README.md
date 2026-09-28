# ai-scan — Gate 2 (Commit) del ciclo de controles de seguridad IA

Escáner que corre en el pipeline de la plataforma de CI/CD y verifica los controles de seguridad IA del baseline

Forma la capa específica de IA del **Gate 2**, junto con dos capas nativas:

| Capa | Provee | Qué cubre |
|------|--------|-----------|
| SAST nativo | Plataforma de CI/CD | Patrones inseguros en el código fuente. |
| Secret Detection nativo | Plataforma de CI/CD (motor gitleaks gestionado) | Secretos genéricos, con ciclo de vida de vulnerabilidades para auditoría. |
| `ai-scan` | Desarrollo propio | Lo específico de IA que lo nativo no entiende. |

> `ai-scan` mantiene `SEC-001` sólo para claves de IA/gateway, con contexto de dominio y mapeo regulatorio.

## Fase actual: WARN (no bloqueante)

`ai-scan` corre con `allow_failure: true` y `--mode warn` (exit 0 siempre).
Reporta findings con severidad pero no bloquea el merge, para calibrar falsos positivos antes de hacerlo mandatorio.
El paso a `enforce` está documentado en `.gitlab-ci.yml`.

## Modo diff-aware (pre-merge)

En pipelines de merge request, `ai-scan` analiza sólo los archivos cambiados respecto de la base del MR (`--diff-base $CI_MERGE_REQUEST_DIFF_BASE_SHA`). 
Así un MR no se bloquea por deuda preexistente que no tocó. 
En la rama por defecto hace full-scan, que es la foto de baseline de la solución.
Si git no está disponible o la base no resuelve, cae a full-scan con un aviso.

## Controles implementados

| ID      | Dominio          | Qué verifica                                              | Gap / Estándar                |
|---------|------------------|----------------------------------------------------------|-------------------------------|
| AIC-001 | ai_components    | Detecta SDKs de IA (disparador del gate)                 | NIST AI RMF (MAP)             |
| AIC-002 | ai_components    | Uso de MCP                                                | OWASP LLM, MITRE ATLAS        |
| AIC-003 | ai_components    | Tools con side-effects                                   | OWASP LLM, MITRE ATLAS        |
| PR-001  | prompts          | **Input no confiable interpolado en el system prompt**   | Baseline 1.01, OWASP LLM01    |
| PR-002  | prompts          | System prompt hardcodeado sin versionar                  | Baseline 1.01                 |
| PII-001 | pii              | **CUIT/CUIL válido** (checksum mod 11) en datos de prueba | Baseline 1.06, Ley 25.326     |
| PII-002 | pii              | DNI en datos de prueba                                    | Baseline 1.06, Ley 25.326     |
| PII-003 | pii              | Tarjeta (Luhn) en datos de prueba                         | Baseline 1.06, PCI-DSS        |
| PII-004 | pii              | Email en datos de prueba                                  | Baseline 1.06, Ley 25.326     |
| SEC-001 | secrets          | Keys de modelos/gateway hardcodeadas                     | Ley 25.326, BCRA              |

## Uso local

```bash
pip install -r requirements.txt
python -m aiscan.cli scan /ruta/al/repo                              # full-scan (warn)
python -m aiscan.cli scan /ruta/al/repo --diff-base origin/main      # sólo cambios
python -m aiscan.cli scan /ruta/al/repo --mode enforce --threshold blocker   # fase 2
```

Genera en `reports/`:
- `ai-scan-findings.json` — findings crudos.
- `gl-code-quality-report.json` — widget del MR.
- `gl-sast-report.json` — **Security Dashboard / Vulnerability Report**.

## Integración con la plataforma de CI/CD

Ver `.gitlab-ci.yml`. Incluye las plantillas nativas de SAST y Secret Detection, y el job `ai-scan` (diff-aware en MR, full en default branch). 