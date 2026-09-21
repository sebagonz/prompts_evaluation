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
*-promptsonar.sarif
*-pi-auditor.json
```

Un código distinto de cero puede significar que hubo hallazgos; verificar los
archivos de salida antes de considerarlo un fallo técnico.

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
la procedencia/SBOM de la imagen. Este POC no implementa CI/CD, policy gates,
waivers ni gestión corporativa de vulnerabilidades.
