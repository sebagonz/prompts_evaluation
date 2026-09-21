#!/usr/bin/env bash
set -u

TARGET="${1:-prompts}"
REPORTS_DIR="${REPORTS_DIR:-reports}"
AUDITOR="${AUDITOR:-/opt/prompt-injection-auditor/scripts/pi_scan.py}"

mkdir -p "${REPORTS_DIR}"

if [ ! -e "${TARGET}" ]; then
  echo "ERROR: target not found: ${TARGET}" >&2
  exit 2
fi

echo "========================================"
echo " PROMPT SECURITY LOCAL SCAN"
echo "========================================"
echo "Target : ${TARGET}"
echo "Reports: ${REPORTS_DIR}"
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
  mapfile -t PROMPT_FILES < <(find "${TARGET}" -type f \( -name '*.txt' -o -name '*.md' \) | sort)
else
  PROMPT_FILES=("${TARGET}")
fi

if [ "${#PROMPT_FILES[@]}" -eq 0 ]; then
  echo "No .txt or .md prompt files found in ${TARGET}"
  exit 0
fi

overall_status=0

for prompt_file in "${PROMPT_FILES[@]}"; do
  if [[ ! "${prompt_file}" =~ \.(txt|md)$ ]]; then
    echo "Skipping unsupported file: ${prompt_file}"
    continue
  fi

  safe_name="$(echo "${prompt_file}" | sed 's#^\./##; s#[/ ]#-#g; s#[^A-Za-z0-9._-]#_#g')"
  safe_name="${safe_name%.*}"

  promptsonar_json="${REPORTS_DIR}/${safe_name}-promptsonar.json"
  promptsonar_sarif="${REPORTS_DIR}/${safe_name}-promptsonar.sarif"
  auditor_json="${REPORTS_DIR}/${safe_name}-pi-auditor.json"

  echo "----------------------------------------"
  echo "Scanning: ${prompt_file}"
  echo "----------------------------------------"

  echo "[1/3] PromptSonar JSON"
  npx --no-install @promptsonar/cli scan "${prompt_file}" --json --output "${promptsonar_json}"
  promptsonar_json_status=$?
  if [ "${promptsonar_json_status}" -ne 0 ]; then
    overall_status=1
    echo "PromptSonar JSON finished with exit code ${promptsonar_json_status}"
  fi

  echo "[2/3] PromptSonar SARIF"
  npx --no-install @promptsonar/cli scan "${prompt_file}" --sarif --output "${promptsonar_sarif}"
  promptsonar_sarif_status=$?
  if [ "${promptsonar_sarif_status}" -ne 0 ]; then
    overall_status=1
    echo "PromptSonar SARIF finished with exit code ${promptsonar_sarif_status}"
  fi

  echo "[3/3] prompt-injection-auditor JSON"
  python3 "${AUDITOR}" "${prompt_file}" --json "${auditor_json}"
  auditor_status=$?
  if [ "${auditor_status}" -ne 0 ]; then
    overall_status=1
    echo "prompt-injection-auditor finished with exit code ${auditor_status}"
  fi

  echo "Reports:"
  echo "  ${promptsonar_json}"
  echo "  ${promptsonar_sarif}"
  echo "  ${auditor_json}"
  echo ""
done

echo "========================================"
echo " SCAN COMPLETE"
echo "========================================"

if [ "${overall_status}" -ne 0 ]; then
  echo "One or more scanners reported findings or execution errors."
else
  echo "No blocking findings reported by the local scanners."
fi

exit "${overall_status}"
