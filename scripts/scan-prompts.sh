#!/usr/bin/env bash
set -u

TARGET="${1:-prompts}"
REPORTS_DIR="${REPORTS_DIR:-reports}"
AUDITOR="${AUDITOR:-/opt/prompt-injection-auditor/scripts/pi_scan.py}"
PI_AUDITOR_TO_SARIF="${PI_AUDITOR_TO_SARIF:-/usr/local/bin/pi-auditor-to-sarif}"
SCAN_SUMMARY="${SCAN_SUMMARY:-/usr/local/bin/build-scan-summary}"
# GitLab ejecuta los jobs desde $CI_PROJECT_DIR, no desde el WORKDIR de la
# imagen. PromptSonar se instala durante el build en este directorio.
PROMPTSONAR_PROJECT_DIR="${PROMPTSONAR_PROJECT_DIR:-/workspace}"

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
summary_args=()

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
  local findings_are_valid="$4"

  # Un status 1 sólo es un finding si el scanner dejó evidencia del análisis.
  # Sin reporte, normalmente es una dependencia ausente, argumento inválido o
  # error de ejecución; no debe confundirse con un hallazgo de seguridad.
  if [ ! -s "${report_path}" ]; then
    execution_errors=1
    prompt_execution_errors=1
    echo "ERROR: ${step_name}: no report was generated at ${report_path} (exit code ${status})." >&2
    return
  fi

  case "${status}" in
    0)
      echo "${step_name}: completed with no blocking findings."
      ;;
    1)
      if [ "${findings_are_valid}" = "true" ]; then
        findings_detected=1
        prompt_findings_detected=1
        echo "${step_name}: blocking findings detected (exit code 1)."
      else
        execution_errors=1
        prompt_execution_errors=1
        echo "ERROR: ${step_name}: unexpected exit code 1." >&2
      fi
      ;;
    *)
      execution_errors=1
      prompt_execution_errors=1
      echo "ERROR: ${step_name}: execution failed (exit code ${status})." >&2
      ;;
  esac
}

print_promptsonar_findings() {
  local report_path="$1"

  # PromptSonar deja el detalle de findings en JSON. Lo mostramos una vez,
  # después de su salida JSON, con prefijo inequívoco para el log de CI.
  python3 - "${report_path}" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as report_file:
        report = json.load(report_file)
except (OSError, json.JSONDecodeError) as error:
    print(f"[PROMPTSONAR] WARNING: cannot summarize findings: {error}")
    raise SystemExit(0)

findings = report.get("findings", [])
if not isinstance(findings, list) or not findings:
    print("[PROMPTSONAR] Findings: none")
    raise SystemExit(0)

print(f"[PROMPTSONAR] Findings reported: {len(findings)}")
for finding in findings:
    if not isinstance(finding, dict):
        continue
    severity = str(finding.get("severity", "unknown")).upper()
    rule_id = str(finding.get("rule_id", "unknown-rule"))
    line = finding.get("line")
    location = f" line {line}" if isinstance(line, int) and line > 0 else ""
    message = " ".join(str(finding.get("message", "No message")).split())
    print(f"[PROMPTSONAR][{severity}][{rule_id}]{location}: {message}")
PY
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
  prompt_findings_detected=0
  prompt_execution_errors=0

  # Evita que un reporte de una ejecución previa haga parecer exitoso a un
  # scanner que falló antes de generar su salida actual.
  rm -f "${promptsonar_json}" "${promptsonar_sarif}" "${auditor_json}" "${auditor_sarif}"

  echo "========================================"
  echo "PROMPT: ${prompt_file}"
  echo "========================================"

  echo "[ANÁLISIS A: PROMPTSONAR]"
  echo "  Cobertura: injection, jailbreak, obfuscación, secretos/PII y agency."
  echo "  Umbral aplicado: ${PROMPTSONAR_FAIL_ON}"
  echo "  [1/4] Generando JSON de PromptSonar"
  run_promptsonar scan \
    "${prompt_file}" \
    --json \
    --output "${promptsonar_json}" \
    "${promptsonar_args[@]}" 2>&1 | sed 's/^/[PROMPTSONAR] /'
  promptsonar_json_status="${PIPESTATUS[0]}"
  record_step_status "PromptSonar JSON" "${promptsonar_json_status}" "${promptsonar_json}" true
  if [ -s "${promptsonar_json}" ]; then
    print_promptsonar_findings "${promptsonar_json}"
  fi

  echo "  [2/4] Generando SARIF de PromptSonar"
  run_promptsonar scan \
    "${prompt_file}" \
    --sarif \
    --output "${promptsonar_sarif}" \
    "${promptsonar_args[@]}" 2>&1 | sed 's/^/[PROMPTSONAR] /'
  promptsonar_sarif_status="${PIPESTATUS[0]}"
  record_step_status "PromptSonar SARIF" "${promptsonar_sarif_status}" "${promptsonar_sarif}" true

  echo ""
  echo "[ANÁLISIS B: PROMPT-INJECTION-AUDITOR / pi_scan.py]"
  echo "  Cobertura: jerarquía de instrucciones, non-disclosure, authority spoofing,"
  echo "  delimitación de contenido no confiable, confirm gates y hardening."
  echo "  [3/4] Generando JSON de prompt-injection-auditor"
  python3 "${AUDITOR}" \
    "${prompt_file}" \
    --json "${auditor_json}" 2>&1 | sed 's/^/[PI-AUDITOR] /'
  auditor_json_status="${PIPESTATUS[0]}"
  record_step_status "prompt-injection-auditor JSON" "${auditor_json_status}" "${auditor_json}" true

  echo ""
  echo "[CONVERSIÓN DE RESULTADOS B: JSON pi-auditor → SARIF 2.1.0]"
  echo "  Nota: este paso no vuelve a analizar el prompt; adapta el resultado"
  echo "  de prompt-injection-auditor para su importación en SonarQube."
  echo "  [4/4] Generando SARIF de prompt-injection-auditor"
  if [ -f "${auditor_json}" ]; then
    python3 "${PI_AUDITOR_TO_SARIF}" "${auditor_json}" --output "${auditor_sarif}" 2>&1 | sed 's/^/[PI-AUDITOR→SARIF] /'
    auditor_sarif_status="${PIPESTATUS[0]}"
    record_step_status "prompt-injection-auditor SARIF conversion" "${auditor_sarif_status}" "${auditor_sarif}" false
  else
    execution_errors=1
    prompt_execution_errors=1
    echo "ERROR: prompt-injection-auditor did not produce ${auditor_json}" >&2
  fi

  echo ""
  echo "Reportes del análisis A — PromptSonar:"
  echo "  JSON : ${promptsonar_json}"
  echo "  SARIF: ${promptsonar_sarif}"
  echo "Reportes del análisis B — prompt-injection-auditor:"
  echo "  JSON : ${auditor_json}"
  echo "  SARIF: ${auditor_sarif}"

  if [ "${prompt_execution_errors}" -ne 0 ]; then
    prompt_result="ERROR"
  elif [ "${prompt_findings_detected}" -ne 0 ]; then
    prompt_result="BLOCK"
  else
    prompt_result="PASS"
  fi
  summary_args+=(--report-pair "${prompt_file}" "${promptsonar_json}" "${auditor_json}" "${prompt_result}")
  echo ""
done

echo "========================================"
echo " SCAN COMPLETE"
echo "========================================"

if [ "${execution_errors}" -ne 0 ]; then
  overall_result="ERROR"
  expected_exit_code=2
elif [ "${findings_detected}" -ne 0 ]; then
  overall_result="BLOCK"
  if [ "${EXIT_ON_FINDINGS}" = "true" ]; then
    expected_exit_code=1
  else
    expected_exit_code=0
  fi
else
  overall_result="PASS"
  expected_exit_code=0
fi

pi_auditor_revision="$(git -C /opt/prompt-injection-auditor rev-parse --short HEAD 2>/dev/null || echo unknown)"
python3 "${SCAN_SUMMARY}" \
  --output "${REPORTS_DIR}/scan-summary.json" \
  --target "${TARGET}" \
  --promptsonar-fail-on "${PROMPTSONAR_FAIL_ON}" \
  --exit-on-findings "${EXIT_ON_FINDINGS}" \
  --pi-auditor-revision "${pi_auditor_revision}" \
  --overall-result "${overall_result}" \
  --expected-exit-code "${expected_exit_code}" \
  "${summary_args[@]}"
if [ "$?" -ne 0 ]; then
  echo "ERROR: execution summary could not be generated." >&2
  execution_errors=1
fi

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
