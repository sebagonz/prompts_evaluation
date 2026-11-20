# Contexto actual del proyecto — analizador de prompts

Actualizado: 5 de noviembre de 2026.

## Alcance

Control 1.01: revisión estática de system prompts y templates. Tres fuentes:
PromptSonar 1.5.1, prompt-injection-auditor y el auditor semántico con LLM juez.
Los dos primeros analizan `.txt` y `.md` sin API; el tercero analiza TXT
visibles mediante LiteLLM. No se ejecutan los prompts como una aplicación.
Los hallazgos semánticos son propuestas para revisión humana.

## Arquitectura implementada

Una imagen del analizador, construida con `Dockerfile`: Node 22, Python con
entorno virtual, scanners y scripts/rúbrica instalados. Dependencias semánticas
en `requirements-semantic.txt`. El alias antiguo de Dockerfile semántico usa
la imagen unificada. PostgreSQL y LiteLLM conservan sus propias imágenes.

```text
prompt-static: PromptSonar + pi-auditor ─┐
                                       ├─ consolidate ─ JSON + SARIF ─ SonarQube
prompt-analyzer: harness + LiteLLM ──────┘
```

`scan-prompts` conserva su modo independiente sin LLM. Con
`DEFER_CONSOLIDATION=1` escribe los reportes y un manifiesto para consolidar
desde otro contenedor/job. `semantic-scan` ejecuta directamente el harness,
que reemplaza el resumen anterior al iniciar y registra su estado y código
de salida en `prompt_audit/summary.json`. `--defer-exit` permite consolidar
aun si el auditor termina en ERROR. Una interrupción deja el estado RUNNING;
el consolidador lo rechaza. No hay wrapper ni recibo semántico adicional.

El consolidador admite los conjuntos estáticos tradicionales, el manifiesto
estático y el resumen semántico. Verifica hashes de TXT,
cobertura y duplicados. Un run SARIF por herramienta, rutas relativas al
checkout, rangos de líneas y trazabilidad de citas/modelo/rúbrica/tiempo.

## Política y evidencia

`FAIL_ON=critical` por defecto: único mínimo para publicación y bloqueo de las
tres fuentes. `none` publica todo lo elegible sin bloqueo por severidad.
Los waivers y categorías de PromptSonar se conservan. `EXIT_ON_FINDINGS=false`
registra BLOCK pero devuelve 0; errores técnicos siempre devuelven 2, generan
resumen ERROR y eliminan el SARIF final. `partial_findings` no se publica.

Artefactos finales: `reports/prompt-security-scan-summary.json` y
`reports/prompt-security-scan.sarif`. Entradas intermedias: manifiesto y SARIF
estáticos, JSON originales y `prompt_audit/`. El resumen
reúne las tres fuentes por prompt y en totales; stdout muestra decisiones y
errores. No hay caché para omitir automáticamente auditorías repetidas.

## Local y GitLab

`./scripts/start-local.sh` crea secretos locales, inicia el proxy/DB, aprovisiona
una clave virtual y ejecuta el flujo completo. Después del setup se puede usar
`docker compose up --build`. `docker compose run --rm prompt-security` conserva
el flujo sin API. El semántico separado usa `docker compose run --rm --no-deps
prompt-analyzer prompts`; ese comando sí consume API. No ejecutar dos corridas
sobre la misma carpeta de reportes.

GitLab ejecuta scanners separados, recoge sus artefactos y consolida antes del
job Sonar. `RUN_SEMANTIC_SCAN=false` por defecto; al habilitarlo requiere URL,
clave virtual y alias en variables CI. La imagen consumida y registry.properties
se alinean en 1.1.0; debe publicarse por el mecanismo corporativo antes de usarla.
La plantilla corporativa de build/publicación no está en este checkout.

## Validación y límites

Pruebas del harness original más pruebas de consolidación, con mocks y un
servidor HTTP en loopback. Usar Docker con `--network none` para garantizar
que no se contacten proveedores. No se ejecutaron auditorías reales para esta
integración. La importación remota y el quality gate de Sonar deben validarse
en el ambiente del cliente; el gate de Sonar es independiente del gate local.
La imagen efectiva del job Sonar sigue definida por `DC_IMAGE_BUILD`.

`AUDITOR_REF=main` y TLS de npm/Git mantienen la configuración del laboratorio.
El build semántico descarga paquetes Python verificando TLS; en redes con
inspección se debe instalar la CA corporativa en vez de desactivar esa validación.
`renato/`, ZIPs y propuestas históricas no participan del flujo activo.

Ver [README.md](README.md) para comandos, parámetros y despliegue; ver
[CONTEXTO_ANALIZADOR_SEMANTICO.md](CONTEXTO_ANALIZADOR_SEMANTICO.md) para el
contrato detallado heredado y su estado de integración.
