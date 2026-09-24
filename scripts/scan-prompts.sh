#!/usr/bin/env bash
set -u

TARGET="${1:-prompts}"
REPORTS_DIR="${REPORTS_DIR:-reports}"
AUDITOR="${AUDITOR:-/opt/prompt-injection-auditor/scripts/pi_scan.py}"
PI_AUDITOR_TO_SARIF="${PI_AUDITOR_TO_SARIF:-/usr/local/bin/pi-auditor-to-sarif}"

# Política global del wrapper:
# true  -> el script retorna 1 si algún scanner reporta un finding bloqueante.
# false -> el script genera reportes, pero retorna 0 aunque haya findings.
EXIT_ON_FINDINGS="${EXIT_ON_FINDINGS:-true}"

# Política de PromptSonar. Debe coincidir con los valores admitidos por su CLI.
# Ejemplos habituales: critical, high, medium, low, none.
PROMPTSONAR_FAIL_ON="${PROMPTSONAR_FAIL_ON:-critical}"

# Opcionales. Déjalos vacíos si no los usas.
PROMPTSONAR_WAIVER="${PROMPTSONAR_WAIVER:-}"
PROMPTSONAR_POLICY_FILE="${PROMPTSONAR_POLICY_FILE:-}"

mkdir -p "${REPORTS_DIR}"

if [ ! -e "${TARGET}" ]; then
  echo "ERROR: target not found: ${TARGET}" >&2
  exit 2
fi

case "${EXIT_ON_FINDINGS}" in
  true|false)
    ;;
  *)
    echo "ERROR: EXIT_ON_FINDINGS must be true or false; received: ${EXIT_ON_FINDINGS}" >&2
    exit 2
    ;;
esac

echo "========================================"
echo " PROMPT SECURITY LOCAL SCAN"
echo "========================================"
echo "Target              : ${TARGET}"
echo "Reports             : ${REPORTS_DIR}"
echo "PromptSonar fail-on : ${PROMPTSONAR_FAIL_ON}"
echo "Exit on findings    : ${EXIT_ON_FINDINGS}"
echo ""

echo "Tool versions"
echo "-------------"
node --version
npm --version
python3 --version
npx --no-install @promptsonar/cli --version 2>/dev/null || true
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

# Construye argumentos de PromptSonar una sola vez.
# El umbral se aplica tanto a JSON como a SARIF.
promptsonar_args=(--fail-on "${PROMPTSONAR_FAIL_ON}")

if [ -n "${PROMPTSONAR_WAIVER}" ]; then
  promptsonar_args+=(--waiver "${PROMPTSONAR_WAIVER}")
fi

if [ -n "${PROMPTSONAR_POLICY_FILE}" ]; then
  promptsonar_args+=(--policy-file "${PROMPTSONAR_POLICY_FILE}")
fi

findings_detected=0
execution_errors=0

record_scanner_status() {
  local scanner_name="$1"
  local status="$2"

  case "${status}" in
    0)
      echo "${scanner_name}: completed with no blocking findings."
      ;;
    1)
      findings_detected=1
      echo "${scanner_name}: blocking findings detected (exit code 1)."
      ;;
    *)
      execution_errors=1
      echo "ERROR: ${scanner_name}: execution failed (exit code ${status})." >&2
      ;;
  esac
}

for prompt_file in "${PROMPT_FILES[@]}"; do
  if [[ ! "${prompt_file}" =~ \.(txt|md)$ ]]; then
    echo "Skipping unsupported file: ${prompt_file}"
    continue
  fi

  safe_name="$(
    echo "${prompt_file}" |
      sed 's#^\./##; s#[/ ]#-#g; s#[^A-Za-z0-9._-]#_#g'
  )"
  safe_name="${safe_name%.*}"

  promptsonar_json="${REPORTS_DIR}/${safe_name}-promptsonar.json"
  promptsonar_sarif="${REPORTS_DIR}/${safe_name}-promptsonar.sarif"
  auditor_json="${REPORTS_DIR}/${safe_name}-pi-auditor.json"
  auditor_sarif="${REPORTS_DIR}/${safe_name}-pi-auditor.sarif"

  echo "----------------------------------------"
  echo "Scanning: ${prompt_file}"
  echo "----------------------------------------"

  echo "[1/3] PromptSonar JSON"
  npx --no-install @promptsonar/cli scan \
    "${prompt_file}" \
    --json \
    --output "${promptsonar_json}" \
    "${promptsonar_args[@]}"
  record_scanner_status "PromptSonar JSON" "$?"

  echo "[2/3] PromptSonar SARIF"
  npx --no-install @promptsonar/cli scan \
    "${prompt_file}" \
    --sarif \
    --output "${promptsonar_sarif}" \
    "${promptsonar_args[@]}"
  record_scanner_status "PromptSonar SARIF" "$?"

  echo "[3/4] prompt-injection-auditor JSON"
  python3 "${AUDITOR}" \
    "${prompt_file}" \
    --json "${auditor_json}"
  record_scanner_status "prompt-injection-auditor JSON" "$?"

  echo "[4/4] prompt-injection-auditor SARIF"
  if [ -f "${auditor_json}" ]; then
    python3 "${PI_AUDITOR_TO_SARIF}" "${auditor_json}" --output "${auditor_sarif}"
    record_scanner_status "prompt-injection-auditor SARIF" "$?"
  else
    execution_errors=1
    echo "ERROR: prompt-injection-auditor did not produce ${auditor_json}" >&2
  fi

  echo "Reports:"
  echo "  ${promptsonar_json}"
  echo "  ${promptsonar_sarif}"
  echo "  ${auditor_json}"
  echo "  ${auditor_sarif}"
  echo ""
done

echo "========================================"
echo " SCAN COMPLETE"
echo "========================================"

if [ "${execution_errors}" -ne 0 ]; then
  echo "Scan completed with one or more execution errors." >&2
  exit 2
fi

if [ "${findings_detected}" -ne 0 ]; then
  echo "Scan completed with blocking security findings."

  if [ "${EXIT_ON_FINDINGS}" = "true" ]; then
    echo "Returning exit code 1 because blocking findings were detected."
    exit 1
  fi

  echo "Returning exit code 0 because EXIT_ON_FINDINGS=false."
  exit 0
fi

echo "Scan completed successfully. No blocking findings were detected."
exit 0
