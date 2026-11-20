FROM node:22-bookworm-slim AS prompt-scanner

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
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY certs/ /usr/local/share/ca-certificates/prompt-scanner/
RUN update-ca-certificates
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

COPY package.json ./
RUN npm config set strict-ssl "${NPM_STRICT_SSL}" \
    && npm install --omit=dev \
    && npm cache clean --force

# POC de laboratorio: la validación TLS se configura mediante los ARG de build.
RUN git -c http.sslVerify="${GIT_SSL_VERIFY}" clone --depth 1 --branch "${AUDITOR_REF}" "${AUDITOR_REPO}" /opt/prompt-injection-auditor

COPY requirements-semantic.txt /opt/prompt-scanner/requirements-semantic.txt
RUN python3 -m venv /opt/prompt-scanner/venv \
    && /opt/prompt-scanner/venv/bin/pip install --no-cache-dir -r /opt/prompt-scanner/requirements-semantic.txt
ENV PATH="/opt/prompt-scanner/venv/bin:/workspace/node_modules/.bin:${PATH}" \
    AUDIT_RUBRIC_PATH=/opt/prompt-scanner/scripts/audit_rubric.md \
    PYTHONUNBUFFERED=1 \
    LITELLM_LOCAL_MODEL_COST_MAP=true \
    DO_NOT_TRACK=1
COPY scripts/ /opt/prompt-scanner/scripts/
RUN ln -s /opt/prompt-scanner/scripts/semantic_scan_prompts.py /usr/local/bin/semantic-scan

COPY scripts/scan-prompts.sh /usr/local/bin/scan-prompts
COPY scripts/consolidate_scan_reports.py /usr/local/bin/consolidate-scan-reports
RUN chmod 0555 /usr/local/bin/scan-prompts /usr/local/bin/consolidate-scan-reports \
    /opt/prompt-scanner/scripts/semantic_scan_prompts.py

# El usuario efectivo se puede reemplazar desde Compose por el UID/GID del
# operador para que los reportes montados queden accesibles en Linux/SUSE.
ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["scan-prompts"]
