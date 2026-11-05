#!/usr/bin/env bash
set -u

TARGET="${1:-prompts}"
REPORTS_DIR="${REPORTS_DIR:-reports}"
AUDITOR="${AUDITOR:-/opt/prompt-injection-auditor/scripts/pi_scan.py}"
CONSOLIDATOR="${CONSOLIDATOR:-/usr/local/bin/consolidate-scan-reports}"

# true: retorna 1 cuando el consolidado detecta findings bloqueantes.
# false: genera reportes y retorna 0 ante findings; errores técnicos siguen siendo 2.
EXIT_ON_FINDINGS="${EXIT_ON_FINDINGS:-true}"

# Umbral común aplicado por el consolidator:
# critical | high | medium | low | none
FAIL_ON="${FAIL_ON:-critical}"
FAIL_ON="${FAIL_ON,,}"

# Opcionales de PromptSonar.
PROMPTSONAR_WAIVER="${PROMPTSONAR_WAIVER:-}"
PROMPTSONAR_POLICY_FILE="${PROMPTSONAR_POLICY_FILE:-}"

# Categorías de PromptSonar que se publican al SARIF consolidado para SonarQube.
PROMPTSONAR_SONAR_CATEGORIES="${PROMPTSONAR_SONAR_CATEGORIES:-security}"

require_command() {
  local command_name="$1"

  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "ERROR: required command not found in PATH: ${command_name}" >&2
    exit 2
  fi
}

if [ ! -e "${TARGET}" ]; then
  echo "ERROR: target not found: ${TARGET}" >&2
  exit 2
fi

if [ ! -f "${AUDITOR}" ]; then
  echo "ERROR: prompt-injection-auditor not found: ${AUDITOR}" >&2
  exit 2
fi

if [ ! -f "${CONSOLIDATOR}" ]; then
  echo "ERROR: consolidator not found: ${CONSOLIDATOR}" >&2
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

case "${FAIL_ON}" in
  critical|high|medium|low|none)
    ;;
  *)
    echo "ERROR: FAIL_ON must be critical, high, medium, low or none; received: ${FAIL_ON}" >&2
    exit 2
    ;;
esac

require_command node
require_command npm
require_command python3
require_command promptsonar
require_command git

# Convierte el target a una ruta absoluta. Esto permite que el mismo script
# funcione desde Docker Compose (/workspace) y GitLab CI ($CI_PROJECT_DIR).
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

echo "========================================"
echo " PROMPT SECURITY SCAN"
echo "========================================"
echo "Target              : ${TARGET_DISPLAY}"
echo "Resolved target     : ${TARGET}"
echo "Reports             : ${REPORTS_DIR}"
echo "FAIL_ON             : ${FAIL_ON}"
echo "Sonar categories    : ${PROMPTSONAR_SONAR_CATEGORIES}"
echo "Exit on findings    : ${EXIT_ON_FINDINGS}"
echo ""

echo "Tool versions"
echo "-------------"
node --version
npm --version
promptsonar --version
python3 --version
git -C /opt/prompt-injection-auditor rev-parse --short HEAD 2>/dev/null || true
echo ""

if [ -d "${TARGET}" ]; then
  mapfile -t PROMPT_FILES < <(
    find "${TARGET}" -type f \( -name '*.txt' -o -name '*.md' \) | sort
  )
else
  PROMPT_FILES=("${TARGET}")
fi



# PromptSonar siempre genera evidencia sin bloquear.
# El consolidator aplica el umbral común FAIL_ON sobre los resultados.
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

if [ "${DEFER_CONSOLIDATION:-0}" = "1" ]; then
  # Estos SARIF son insumos de otro contenedor/job; deben persistir.
  sarif_work_dir="${REPORTS_DIR}/static-sarif"
  mkdir -p "${sarif_work_dir}"
else
  sarif_work_dir="$(mktemp -d "${TMPDIR:-/tmp}/prompt-security-sarif.XXXXXX")"
  trap 'rm -rf "${sarif_work_dir}"' EXIT
fi

rm -f "${unified_sarif}" "${summary_json}"

record_step_status() {
  local step_name="$1"
  local status="$2"
  local report_path="$3"
  local scanner_kind="$4"

  if [ ! -s "${report_path}" ]; then
    execution_errors=1
    echo "ERROR: ${step_name}: report was not generated: ${report_path} (exit code ${status})." >&2
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
        echo "${step_name}: PromptSonar policy failed (exit code 1)."
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

  rm -f \
    "${promptsonar_json}" \
    "${promptsonar_sarif}" \
    "${auditor_json}"

  echo "========================================"
  echo "PROMPT: ${prompt_file_display}"
  echo "========================================"

  echo "[ANALYSIS A: PROMPTSONAR]"
  echo "  Coverage: injection, jailbreak, obfuscation, secrets/PII and agency."
  echo "  [1/3] Generating PromptSonar JSON"

  promptsonar scan \
    "${prompt_file}" \
    --json \
    --output "${promptsonar_json}" \
    "${promptsonar_args[@]}" 2>&1 | sed 's/^/[PROMPTSONAR] /'

  promptsonar_json_status="${PIPESTATUS[0]}"
  record_step_status \
    "PromptSonar JSON" \
    "${promptsonar_json_status}" \
    "${promptsonar_json}" \
    "promptsonar"

  echo "  [2/3] Generating PromptSonar SARIF"

  promptsonar scan \
    "${prompt_file}" \
    --sarif \
    --output "${promptsonar_sarif}" \
    "${promptsonar_args[@]}" 2>&1 | sed 's/^/[PROMPTSONAR] /'

  promptsonar_sarif_status="${PIPESTATUS[0]}"
  record_step_status \
    "PromptSonar SARIF" \
    "${promptsonar_sarif_status}" \
    "${promptsonar_sarif}" \
    "promptsonar"

  echo ""
  echo "[ANALYSIS B: PROMPT-INJECTION-AUDITOR]"
  echo "  [3/3] Generating prompt-injection-auditor JSON"

  python3 "${AUDITOR}" \
    "${prompt_file}" \
    --json "${auditor_json}" 2>&1 | sed 's/^/[PI-AUDITOR] /'

  auditor_json_status="${PIPESTATUS[0]}"
  record_step_status \
    "prompt-injection-auditor JSON" \
    "${auditor_json_status}" \
    "${auditor_json}" \
    "auditor"

  report_args+=(
    --report-set
    "${prompt_file_display}"
    "${promptsonar_json}"
    "${promptsonar_sarif}"
    "${auditor_json}"
  )

  if [ "${prompt_governance_failed}" -ne 0 ]; then
    governance_args+=(--governance-failed "${prompt_file_display}")
  fi

  echo ""
done

echo "========================================"
echo " CONSOLIDATING SARIF REPORTS"
echo "========================================"

consolidator_args=(
  --target "${TARGET_DISPLAY}"
  --output-sarif "${unified_sarif}"
  --output-summary "${summary_json}"
  --fail-on "${FAIL_ON}"
  --promptsonar-categories "${PROMPTSONAR_SONAR_CATEGORIES}"
  --exit-on-findings "${EXIT_ON_FINDINGS}"
  --pi-auditor-revision "$(
    git -C /opt/prompt-injection-auditor rev-parse --short HEAD 2>/dev/null || echo unknown
  )"
)

if [ "${execution_errors}" -ne 0 ]; then
  consolidator_args+=(--scanner-error)
fi

if [ "${DEFER_CONSOLIDATION:-0}" = "1" ]; then
  python3 - "${REPORTS_DIR}/static-scan-manifest.json" \
    "${consolidator_args[@]}" "${governance_args[@]}" "${report_args[@]}" <<'MANIFEST'
import hashlib
import json
import os
import sys
from pathlib import Path
# Rutas relativas al checkout para transportar los artefactos entre jobs.
root = str(Path.cwd()) + "/"
args = [value[len(root):] if value.startswith(root) else value for value in sys.argv[2:]]
path = Path(sys.argv[1])
temporary = path.with_suffix(".tmp")
sources = {args[index + 1]: hashlib.sha256(Path(args[index + 1]).read_bytes()).hexdigest()
           for index, value in enumerate(args) if value == "--report-set"}
temporary.write_text(json.dumps({"arguments": args, "source_hashes": sources}, indent=2) + "\n", encoding="utf-8")
os.replace(temporary, path)
MANIFEST
  exit $?
fi

python3 "${CONSOLIDATOR}" \
  "${consolidator_args[@]}" \
  "${governance_args[@]}" \
  "${report_args[@]}"

exit $?
