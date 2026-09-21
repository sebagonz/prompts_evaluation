FROM node:22-bookworm-slim

ARG AUDITOR_REPO=https://github.com/screem500/prompt-injection-auditor.git
ARG AUDITOR_REF=main
ARG NPM_STRICT_SSL=false
ARG GIT_SSL_VERIFY=false

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        git \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm config set strict-ssl "${NPM_STRICT_SSL}" \
    && npm install --omit=dev \
    && npm cache clean --force

# POC de laboratorio: la validación TLS se configura mediante los ARG de build.
RUN git -c http.sslVerify="${GIT_SSL_VERIFY}" clone --depth 1 --branch "${AUDITOR_REF}" "${AUDITOR_REPO}" /opt/prompt-injection-auditor

COPY scripts/scan-prompts.sh /usr/local/bin/scan-prompts
RUN chmod 0555 /usr/local/bin/scan-prompts

# El usuario efectivo se puede reemplazar desde Compose por el UID/GID del
# operador para que los reportes montados queden accesibles en Linux/SUSE.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["scan-prompts"]
