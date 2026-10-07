#!/usr/bin/env bash
set -u

TARGET="${1:-prompts}"
REPORTS_DIR="${REPORTS_DIR:-reports}"
AUDITOR="${AUDITOR:-/opt/prompt-injection-auditor/scripts/pi_scan.py}"
CONSOLIDATOR="${CONSOLIDATOR:-/usr/local/bin/consolidate-scan-reports}"
# GitLab ejecuta los jobs desde $CI_PROJECT_DIR, no desde el WORKDIR de la
# imagen. PromptSonar se instala durante el build en este directorio.
PROMPTSONAR_PROJECT_DIR="${PROMPTSONAR_PROJECT_DIR:-/workspace}"

# Política global del wrapper:
# true  -> el script retorna 1 si algún scanner reporta un finding bloqueante.
# false -> el script genera reportes, pero retorna 0 aunque haya findings.
EXIT_ON_FINDINGS="${EXIT_ON_FINDINGS:-true}"

# Umbral único para el gate y el SARIF final.
FAIL_ON="${FAIL_ON:-critical}"
FAIL_ON="${FAIL_ON,,}"

# Opcionales. Déjalos vacíos si no los usas.
PROMPTSONAR_WAIVER="${PROMPTSONAR_WAIVER:-}"
PROMPTSONAR_POLICY_FILE="${PROMPTSONAR_POLICY_FILE:-}"
# Categorías de PromptSonar que se publican en Sonar; el JSON conserva todas.
PROMPTSONAR_SONAR_CATEGORIES="${PROMPTSONAR_SONAR_CATEGORIES:-security}"

if [ ! -e "${TARGET}" ]; then
  echo "ERROR: target not found: ${TARGET}" >&2
  exit 2
fi

# El job de GitLab monta el repositorio en $CI_PROJECT_DIR, mientras que las
# dependencias de PromptSonar viven en /workspace dentro de la imagen. Como la
# CLI se ejecuta desde ese último directorio, las rutas relativas del repositorio
# dejarían de apuntar a los prompts. Normalizamos las rutas antes de cambiar de
# directorio para que ambos scanners lean el mismo archivo del checkout.
SCAN_WORK_DIR="$(pwd -P)"
TARGET_DISPLAY="${TARGET}"
if [ -d "${TARGET}" ]; then
  TARGET="$(cd "${TARGET}" && pwd -P)"
else
  target_dir="$(dirname "${TARGET}")"
  target_base="$(basename "${TARGET}")"
  TARGET="$(cd "${target_dir}" && printf '%s/%s\n' "$(pwd -P)" "${target_base}")"
fi

mkdir -p "${REPORTS_DIR}"
reports_dir_parent="$(dirname "${REPORTS_DIR}")"
reports_dir_base="$(basename "${REPORTS_DIR}")"
REPORTS_DIR="$(cd "${reports_dir_parent}" && printf '%s/%s\n' "$(pwd -P)" "${reports_dir_base}")"

case "${EXIT_ON_FINDINGS}" in
  true|false)
    ;;
  *)
    echo "ERROR: EXIT_ON_FINDINGS must be true or false; received: ${EXIT_ON_FINDINGS}" >&2
    exit 2
    ;;
esac

case "${FAIL_ON}" in
  critical|high|medium|low|none) ;;
  *)
    echo "ERROR: FAIL_ON must be critical, high, medium, low or none; received: ${FAIL_ON}" >&2
    exit 2
    ;;
esac

echo "========================================"
echo " PROMPT SECURITY LOCAL SCAN"
echo "========================================"
echo "Target              : ${TARGET_DISPLAY}"
echo "Reports             : ${REPORTS_DIR}"
echo "Umbral único FAIL_ON: ${FAIL_ON} (none = publicar todo sin bloquear)"
echo "Sonar categories    : ${PROMPTSONAR_SONAR_CATEGORIES}"
echo "Exit on findings    : ${EXIT_ON_FINDINGS}"
echo ""

echo "Tool versions"
echo "-------------"
node --version
npm --version
python3 --version
if [ -d "${PROMPTSONAR_PROJECT_DIR}/node_modules/@promptsonar/cli" ]; then
  (
    cd "${PROMPTSONAR_PROJECT_DIR}" &&
      npx --no-install @promptsonar/cli --version
  ) || true
else
  echo "PromptSonar: NOT INSTALLED in ${PROMPTSONAR_PROJECT_DIR}"
fi
git -C /opt/prompt-injection-auditor rev-parse --short HEAD 2>/dev/null || true
echo ""

if [ -d "${TARGET}" ]; then
  mapfile -t PROMPT_FILES < <(
    find "${TARGET}" -type f \( -name '*.txt' -o -name '*.md' \) | sort
  )
else
  PROMPT_FILES=("${TARGET}")
fi

if [ "${#PROMPT_FILES[@]}" -eq 0 ]; then
  echo "No .txt or .md prompt files found in ${TARGET}"
  exit 0
fi

# ANÁLISIS A — PromptSonar:
# detección estática de injection/jailbreak, obfuscación, secretos/PII,
# context isolation, workflow escalation y privileged sinks.
# La CLI sólo genera evidencia; el gate común aplica FAIL_ON a ambos JSON.
promptsonar_args=(--fail-on none)

if [ -n "${PROMPTSONAR_WAIVER}" ]; then
  promptsonar_args+=(--waiver "${PROMPTSONAR_WAIVER}")
fi

if [ -n "${PROMPTSONAR_POLICY_FILE}" ]; then
  promptsonar_args+=(--policy-file "${PROMPTSONAR_POLICY_FILE}")
fi

execution_errors=0
report_args=()
governance_args=()
unified_sarif="${REPORTS_DIR}/prompt-security-scan.sarif"
summary_json="${REPORTS_DIR}/prompt-security-scan-summary.json"
sarif_work_dir="$(mktemp -d "${TMPDIR:-/tmp}/prompt-security-sarif.XXXXXX")"
trap 'rm -rf "${sarif_work_dir}"' EXIT

run_promptsonar() {
  if [ ! -d "${PROMPTSONAR_PROJECT_DIR}/node_modules/@promptsonar/cli" ]; then
    echo "ERROR: PromptSonar is not installed in ${PROMPTSONAR_PROJECT_DIR}." >&2
    echo "Rebuild the scanner image from this Dockerfile; do not install packages during the CI job." >&2
    return 127
  fi

  (
    cd "${PROMPTSONAR_PROJECT_DIR}" || exit 127
    npx --no-install @promptsonar/cli "$@"
  )
}

record_step_status() {
  local step_name="$1"
  local status="$2"
  local report_path="$3"
  local scanner_kind="$4"

  # PromptSonar ejecuta con --fail-on none; un código no cero indica error o
  # incumplimiento de una policy-file externa. El auditor usa 1 para findings.
  # Sin reporte, normalmente es una dependencia ausente, argumento inválido o
  # error de ejecución; no debe confundirse con un hallazgo de seguridad.
  if [ ! -s "${report_path}" ]; then
    execution_errors=1
    echo "ERROR: ${step_name}: no report was generated at ${report_path} (exit code ${status})." >&2
    return
  fi

  case "${status}" in
    0)
      echo "${step_name}: report generated."
      ;;
    1)
      if [ "${scanner_kind}" = "auditor" ]; then
        echo "${step_name}: scanner reported findings (exit code 1)."
      elif [ "${scanner_kind}" = "promptsonar" ] && [ -n "${PROMPTSONAR_POLICY_FILE}" ]; then
        prompt_governance_failed=1
        echo "${step_name}: PromptSonar governance policy failed (exit code 1)."
      else
        execution_errors=1
        echo "ERROR: ${step_name}: unexpected exit code 1." >&2
      fi
      ;;
    *)
      execution_errors=1
      echo "ERROR: ${step_name}: execution failed (exit code ${status})." >&2
      ;;
  esac
}

for prompt_file in "${PROMPT_FILES[@]}"; do
  if [[ ! "${prompt_file}" =~ \.(txt|md)$ ]]; then
    echo "Skipping unsupported file: ${prompt_file}"
    continue
  fi

  # Mantiene nombres de artefacto legibles (p. ej. prompts/foo-promptsonar)
  # aunque PromptSonar reciba la ruta absoluta requerida dentro de la imagen.
  prompt_file_display="${prompt_file#"${SCAN_WORK_DIR}/"}"

  safe_name="$(
    echo "${prompt_file_display}" |
      sed 's#^\./##; s#[/ ]#-#g; s#[^A-Za-z0-9._-]#_#g'
  )"
  safe_name="${safe_name%.*}"

  promptsonar_json="${REPORTS_DIR}/${safe_name}-promptsonar.json"
  promptsonar_sarif="${sarif_work_dir}/${safe_name}-promptsonar.sarif"
  auditor_json="${REPORTS_DIR}/${safe_name}-pi-auditor.json"
  prompt_governance_failed=0

  # Evita que un reporte de una ejecución previa haga parecer exitoso a un
  # scanner que falló antes de generar su salida actual.
  rm -f "${promptsonar_json}" "${auditor_json}" "${promptsonar_sarif}" \
    "${unified_sarif}" "${summary_json}"

  echo "========================================"
  echo "PROMPT: ${prompt_file_display}"
  echo "========================================"

  echo "[ANÁLISIS A: PROMPTSONAR]"
  echo "  Cobertura: injection, jailbreak, obfuscación, secretos/PII y agency."
  echo "  Umbral de publicación y gate: ${FAIL_ON}"
  echo "  [1/3] Generando JSON de PromptSonar"
  run_promptsonar scan \
    "${prompt_file}" \
    --json \
    --output "${promptsonar_json}" \
    "${promptsonar_args[@]}" 2>&1 | sed 's/^/[PROMPTSONAR] /'
  promptsonar_json_status="${PIPESTATUS[0]}"
  record_step_status "PromptSonar JSON" "${promptsonar_json_status}" "${promptsonar_json}" promptsonar

  echo "  [2/3] Generando SARIF original de PromptSonar"
  run_promptsonar scan \
    "${prompt_file}" \
    --sarif \
    --output "${promptsonar_sarif}" \
    "${promptsonar_args[@]}" 2>&1 | sed 's/^/[PROMPTSONAR] /'
  promptsonar_sarif_status="${PIPESTATUS[0]}"
  record_step_status "PromptSonar SARIF" "${promptsonar_sarif_status}" "${promptsonar_sarif}" promptsonar

  echo ""
  echo "[ANÁLISIS B: PROMPT-INJECTION-AUDITOR / pi_scan.py]"
  echo "  Cobertura: jerarquía de instrucciones, non-disclosure, authority spoofing,"
  echo "  delimitación de contenido no confiable, confirm gates y hardening."
  echo "  [3/3] Generando JSON de prompt-injection-auditor"
  python3 "${AUDITOR}" \
    "${prompt_file}" \
    --json "${auditor_json}" 2>&1 | sed 's/^/[PI-AUDITOR] /'
  auditor_json_status="${PIPESTATUS[0]}"
  record_step_status "prompt-injection-auditor JSON" "${auditor_json_status}" "${auditor_json}" auditor

  report_args+=(--report-set "${prompt_file_display}" "${promptsonar_json}" "${promptsonar_sarif}" "${auditor_json}")
  if [ "${prompt_governance_failed}" -ne 0 ]; then
    governance_args+=(--governance-failed "${prompt_file_display}")
  fi
  echo ""
done

echo "========================================"
echo " CONVERTING, FILTERING AND CONSOLIDATING SARIF"
echo "========================================"

consolidator_args=(
  --target "${TARGET_DISPLAY}"
  --output-sarif "${unified_sarif}"
  --output-summary "${summary_json}"
  --fail-on "${FAIL_ON}"
  --promptsonar-categories "${PROMPTSONAR_SONAR_CATEGORIES}"
  --exit-on-findings "${EXIT_ON_FINDINGS}"
  --pi-auditor-revision "$(git -C /opt/prompt-injection-auditor rev-parse --short HEAD 2>/dev/null || echo unknown)"
)
if [ "${execution_errors}" -ne 0 ]; then
  consolidator_args+=(--scanner-error)
fi
python3 "${CONSOLIDATOR}" "${consolidator_args[@]}" "${governance_args[@]}" "${report_args[@]}"
exit $?
