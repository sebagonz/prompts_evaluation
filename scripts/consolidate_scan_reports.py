#!/usr/bin/env python3
"""Prepara el SARIF que el job de SonarQube importa y evalúa el scan gate local.

Recibe, por cada prompt, el JSON y el SARIF originales de PromptSonar y el JSON
de prompt-injection-auditor. Convierte este último a SARIF, relaciona cada
resultado SARIF con su finding JSON, descarta los que no cumplen la política y
fusiona los resultados restantes en un único SARIF con un run por herramienta.
También escribe un resumen JSON. En stdout separa las decisiones de cada
herramienta y, en el resumen por prompt, enumera los findings incluidos en el
SARIF destinado a Sonar y los excluidos con sus motivos.
El script prepara el archivo; la importación efectiva ocurre en el job de Sonar.

Cómo configurar el umbral de publicación y bloqueo:
  --fail-on NIVEL es el único umbral: un finding con esa severidad o una mayor
  se incluye en el SARIF que importa Sonar y bloquea el scan gate local.
  Los niveles, de mayor a menor, son critical, high, medium y low. El valor
  por defecto es critical. Por ejemplo, high incluye y bloquea high y
  critical; medium incluye y bloquea medium, high y critical.
  --fail-on none desactiva el bloqueo por severidad y el filtro de severidad
  del SARIF: publica todos los findings elegibles, incluidos los info.
  Las excepciones vigentes de PromptSonar y las categorías fuera de
  --promptsonar-categories siguen excluidas aunque cumplan el umbral.
  El JSON original conserva todos los findings.

  Ejemplos de política:
    --fail-on critical    Publica y bloquea desde critical (predeterminado).
    --fail-on high        Publica y bloquea desde high.
    --fail-on medium      Publica y bloquea desde medium.
    --fail-on none        Publica todas las severidades elegibles sin bloquear.

  Con el wrapper scan-prompts o Docker Compose se configura FAIL_ON:
    FAIL_ON=medium docker compose run --rm prompt-security prompts
  EXIT_ON_FINDINGS=false conserva el resultado BLOCK en el resumen, pero hace
  que el proceso devuelva 0 para permitir el paso siguiente de la pipeline.

Parámetros de este script (python3 scripts/consolidate_scan_reports.py):
  --target RUTA                   Etiqueta del archivo/directorio; obligatorio.
  --report-set PROMPT PS_JSON PS_SARIF PI_JSON
                                  Cuatro entradas por prompt; repetir; obligatorio.
  --output-sarif RUTA             SARIF consolidado; obligatorio.
  --output-summary RUTA           Resumen JSON; obligatorio.
  --fail-on NIVEL                 Publicación y gate: critical por defecto;
                                  admite high, medium, low y none.
  --promptsonar-categories CSV    Categorías admitidas; security por defecto.
                                  Otras: clarity, structure, best_practices,
                                  consistency, efficiency, ethics.
  --exit-on-findings true|false   Con true (defecto), BLOCK devuelve código 1;
                                  con false, registra BLOCK y devuelve 0.
  --pi-auditor-revision TEXTO     Revisión en el resumen; unknown por defecto.
  --governance-failed PROMPT      Bloqueo por policy de PromptSonar; repetible.
  --scanner-error                 Error técnico: resumen ERROR, salida 2 y
                                  ningún SARIF final.

El código de salida es 0 si el scan pasa (o si BLOCK no debe fallar el job),
1 si BLOCK debe fallarlo y 2 ante un error técnico. El quality gate de SonarQube
es independiente del scan gate calculado aquí.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PROMPTSONAR_CATEGORIES = frozenset((
    "security", "clarity", "structure", "best_practices",
    "consistency", "efficiency", "ethics",
))
PROMPTSONAR_RANK = {"info": 20, "low": 20, "medium": 50, "high": 70, "critical": 90}
TOOL_NAMES = {"promptsonar": "PromptSonar", "pi-auditor": "prompt-injection-auditor"}
SARIF_LEVELS = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def write_json_atomically(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(document, output, indent=2, ensure_ascii=False)
            output.write("\n")
        os.replace(temporary_name, path)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def read_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path}: JSON root must be an object")
    return document


def report_summary(path: Path, tool: str, report: dict[str, Any] | None = None) -> dict[str, Any]:
    if report is None:
        try:
            report = read_json(path)
        except (OSError, ValueError) as error:
            return {"report": str(path), "available": False, "error": str(error),
                    "findings": dict.fromkeys(SEVERITIES, 0), "total_findings": 0}

    counts = dict.fromkeys(SEVERITIES, 0)
    findings = report.get("findings", [])
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                severity = str(finding.get("severity", "unknown")).strip().lower()
                counts[severity if severity in counts else "unknown"] += 1
    summary: dict[str, Any] = {"report": str(path), "available": True,
                               "findings": counts, "total_findings": sum(counts.values())}
    if tool == "promptsonar":
        waived = sum(finding.get("waived") is True for finding in findings
                     if isinstance(finding, dict)) if isinstance(findings, list) else 0
        summary.update(version=report.get("version", "unknown"),
                       overall_risk=report.get("executive_summary", {}).get("overall_risk", "unknown"),
                       waived_findings=waived)
    else:
        summary.update(tool=report.get("tool", TOOL_NAMES["pi-auditor"]),
                       risk_score=report.get("risk_score"), verdict=report.get("verdict", "unknown"))
    return summary


def format_counts(counts: dict[str, int]) -> str:
    return " ".join(f"{severity.title()}={counts.get(severity, 0)}" for severity in SEVERITIES[:4])


def convert_pi_report(report: dict[str, Any]) -> dict[str, Any]:
    """Convierte el JSON del auditor, conservando descripción, remedio y líneas."""
    target = report.get("target")
    findings = report.get("findings")
    if not isinstance(target, str) or not target.strip() or not isinstance(findings, list):
        raise ValueError("pi-auditor: expected target string and findings array")

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("pi-auditor: invalid finding")
        rule_id, severity, title = finding_fields(finding, "pi-auditor")
        detail = finding.get("detail")
        fix = finding.get("fix")
        detail = detail.strip() if isinstance(detail, str) else ""
        fix = fix.strip() if isinstance(fix, str) else ""
        level = SARIF_LEVELS[severity]
        rule: dict[str, Any] = {
            "id": rule_id, "name": rule_id,
            "shortDescription": {"text": title},
            "fullDescription": {"text": detail or title},
            "defaultConfiguration": {"level": level},
            "properties": {"piAuditorSeverity": severity},
        }
        if fix:
            rule["help"] = {"text": fix, "markdown": fix}
        rules.setdefault(rule_id, rule)

        parts = [title] + ([detail] if detail else [])
        markdown_parts = list(parts)
        if fix:
            parts.append(f"Recommended fix: {fix}")
            markdown_parts.append(f"**Recommended fix:** {fix}")
        result: dict[str, Any] = {
            "ruleId": rule_id, "level": level,
            "message": {"text": "\n\n".join(parts), "markdown": "\n\n".join(markdown_parts)},
            "properties": {"piAuditorSeverity": severity, "piAuditorTitle": title},
        }
        lines = finding.get("lines", [])
        if isinstance(lines, list):
            unique_lines = dict.fromkeys(line for line in lines
                                         if type(line) is int and line > 0)
            if unique_lines:
                result["locations"] = [
                    {"physicalLocation": {"artifactLocation": {"uri": target},
                                          "region": {"startLine": line}}}
                    for line in unique_lines
                ]
        results.append(result)

    driver: dict[str, Any] = {
        "name": TOOL_NAMES["pi-auditor"],
        "informationUri": "https://github.com/screem500/prompt-injection-auditor",
        "rules": list(rules.values()),
    }
    if isinstance(report.get("tool"), str) and report["tool"].strip():
        driver["fullName"] = report["tool"].strip()
    run: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    if isinstance(report.get("timestamp"), str) and report["timestamp"].strip():
        run["invocations"] = [{"executionSuccessful": True, "endTimeUtc": report["timestamp"]}]
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def merge_runs(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Agrupa los runs por herramienta y conserva los resultados y reglas únicos."""
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for document in documents:
        for run in document["runs"]:
            driver = run["tool"]["driver"]
            key = (driver["name"], str(driver.get("version", "")),
                   str(driver.get("informationUri", "")))
            if key not in merged:
                merged[key] = copy.deepcopy(run)
                continue
            destination = merged[key]
            destination["results"].extend(copy.deepcopy(run["results"]))
            rules = destination["tool"]["driver"]["rules"]
            existing_ids = {rule["id"] for rule in rules}
            rules.extend(copy.deepcopy(rule) for rule in driver["rules"]
                         if rule["id"] not in existing_ids)
    return list(merged.values())


def finding_fields(finding: dict[str, Any], tool: str) -> tuple[str, str, str]:
    rule_id = finding.get("rule_id" if tool == "promptsonar" else "id")
    severity = finding.get("severity")
    title = finding.get("message" if tool == "promptsonar" else "title")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("a JSON finding has no rule ID")
    if isinstance(severity, str) and severity.lower() == "informational":
        severity = "info"
    if not isinstance(severity, str) or severity.lower() not in SEVERITY_ORDER:
        raise ValueError(f"{rule_id}: unsupported severity {severity!r}")
    if not isinstance(title, str) or not title:
        raise ValueError(f"{rule_id}: missing message or title")
    return rule_id, severity.lower(), title


def matches(result: dict[str, Any], finding: dict[str, Any], tool: str) -> bool:
    rule_id, severity, title = finding_fields(finding, tool)
    if result.get("ruleId") != rule_id:
        return False
    message = result.get("message", {}).get("text", "")
    if not isinstance(message, str) or not message.startswith(title):
        return False
    if tool == "promptsonar":
        return result.get("rank") == PROMPTSONAR_RANK[severity]
    result_severity = result.get("properties", {}).get("piAuditorSeverity")
    return ("info" if result_severity == "informational" else result_severity) == severity


def reaches(severity: str, minimum: str) -> bool:
    return minimum != "none" and SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minimum]


def process_tool(
    report: dict[str, Any], sarif: dict[str, Any], tool: str,
    categories: set[str], fail_on: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
    findings = report.get("findings")
    runs = sarif.get("runs")
    if not isinstance(findings, list) or not isinstance(runs, list) or len(runs) != 1:
        raise ValueError(f"{tool}: expected findings array and exactly one SARIF run")
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if driver.get("name") != TOOL_NAMES[tool]:
        raise ValueError(f"{tool}: unexpected SARIF tool name")
    results = run.get("results")
    rules = driver.get("rules")
    if not isinstance(results, list) or not isinstance(rules, list):
        raise ValueError(f"{tool}: SARIF run has no results or rules array")

    unmatched = list(enumerate(results))
    included = []
    decisions = []
    gate_count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError(f"{tool}: invalid JSON finding")
        rule_id, severity, title = finding_fields(finding, tool)
        match = next(((index, result) for index, result in unmatched
                      if isinstance(result, dict) and matches(result, finding, tool)), None)
        if match is not None:
            unmatched.remove(match)

        scope_reasons = []
        if tool == "promptsonar":
            if finding.get("waived") is True:
                source = finding.get("suppression_source")
                scope_reasons.append(f"excepción vigente ({source})" if source else "excepción vigente")
            category = finding.get("category")
            if category not in categories:
                scope_reasons.append(f"categoría {category!s} fuera de {','.join(sorted(categories))}")

        if not scope_reasons and reaches(severity, fail_on):
            gate_count += 1

        reasons = list(scope_reasons)
        if match is None:
            reasons.append("el scanner no lo exportó al SARIF original")
        if fail_on != "none" and not reaches(severity, fail_on):
            reasons.append(f"severidad {severity} inferior al mínimo {fail_on}")
        if not reasons:
            included.append(match[1])
        decisions.append({"rule_id": rule_id, "severity": severity, "title": title,
                          "included": not reasons, "reasons": reasons})

    if unmatched:
        raise ValueError(f"{tool}: {len(unmatched)} SARIF results have no matching JSON finding")
    run["results"] = included
    active_rules = {result["ruleId"] for result in included}
    driver["rules"] = [rule for rule in rules if rule.get("id") in active_rules]
    return sarif, decisions, gate_count


def print_decisions(prompt: str, tool: str, decisions: list[dict[str, Any]]) -> None:
    print("=" * 64)
    print(f"[{tool}] {prompt}")
    print("=" * 64)
    for included, heading in ((True, "SE PUBLICAN EN SONAR"),
                              (False, "NO SE PUBLICAN EN SONAR")):
        selected = [decision for decision in decisions if decision["included"] is included]
        print(f"  {heading} ({len(selected)}):")
        if not selected:
            print("    (ninguno)")
        for decision in selected:
            title = " ".join(decision["title"].split())
            reason = f" | motivo: {'; '.join(decision['reasons'])}" if not included else ""
            print(f"    [{decision['severity'].upper()}] {decision['rule_id']}: {title}{reason}")


def build_summary(args: argparse.Namespace, prompts: list[dict[str, Any]],
                  overall_result: str, expected_exit_code: int,
                  error: str | None = None) -> dict[str, Any]:
    promptsonar_total = Counter(dict.fromkeys(SEVERITIES, 0))
    auditor_total = Counter(dict.fromkeys(SEVERITIES, 0))
    for prompt in prompts:
        promptsonar_total.update(prompt["promptsonar"]["findings"])
        auditor_total.update(prompt["pi_auditor"]["findings"])
    summary: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "policy": {
            "fail_on": args.fail_on,
            "promptsonar_sonar_categories": sorted(args.categories),
            "exit_on_findings": args.exit_on_findings == "true",
        },
        "tools": {"pi_auditor_revision": args.pi_auditor_revision},
        "prompts": prompts,
        "totals": {"promptsonar": dict(promptsonar_total), "pi_auditor": dict(auditor_total)},
        "overall_result": overall_result,
        "expected_exit_code": expected_exit_code,
    }
    if error:
        summary["error"] = error
    return summary


def print_summary(summary: dict[str, Any], output: Path, sarif_path: Path,
                  published: list[dict[str, Any]], excluded: list[dict[str, Any]]) -> None:
    minimum = summary["policy"]["fail_on"]
    threshold = ("todas las severidades elegibles; sin bloqueo por severidad"
                 if minimum == "none" else f"{minimum} o superior para SARIF y scan gate")
    categories = ",".join(summary["policy"]["promptsonar_sonar_categories"])
    print("========================================")
    print(f" UMBRAL ÚNICO FAIL_ON={minimum.upper()}")
    print(f" Criterio: {threshold}")
    print(f" PromptSonar: categorías {categories}; excepciones excluidas")
    print("========================================")
    print(" EXECUTION SUMMARY BY PROMPT")
    print("========================================")
    for prompt in summary["prompts"]:
        path = prompt["path"]
        print(f"PROMPT: {path}")
        ps = prompt["promptsonar"]
        print(f"  PROMPTSONAR : {format_counts(ps['findings'])} "
              f"(waived={ps.get('waived_findings', 0)})")
        print(f"  PI-AUDITOR  : {format_counts(prompt['pi_auditor']['findings'])}")
        if summary["overall_result"] == "ERROR":
            print("  SONAR       : no se genera SARIF final por un error técnico")
        else:
            for heading, findings in (("SE ENVIAN A SONAR", published),
                                      ("NO SE ENVIAN A SONAR", excluded)):
                selected = [finding for finding in findings if finding["prompt"] == path]
                print(f"  {heading} ({len(selected)}):")
                if not selected:
                    print("    (ninguno)")
                for finding in selected:
                    title = " ".join(finding["title"].split())
                    reason = (f" | motivo: {'; '.join(finding['reasons'])}"
                              if finding["reasons"] else "")
                    print(f"    {finding['tool']} | [{finding['severity'].upper()}] "
                          f"{finding['rule_id']}: {title}{reason}")
        print(f"  RESULT      : {prompt['result']}")
        print("----------------------------------------")
    print(f"TOTAL PROMPTSONAR: {format_counts(summary['totals']['promptsonar'])}")
    print(f"TOTAL PI-AUDITOR : {format_counts(summary['totals']['pi_auditor'])}")
    if summary["overall_result"] != "ERROR":
        print(f"TOTAL A SONAR     : {len(published)}")
        print(f"TOTAL EXCLUIDOS   : {len(excluded)}")
        print(f"SARIF PARA SONAR  : {sarif_path}")
    print(f"OVERALL RESULT   : {summary['overall_result']}")
    print(f"SUMMARY JSON     : {output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-sarif", required=True, type=Path)
    parser.add_argument("--output-summary", required=True, type=Path)
    parser.add_argument("--fail-on", default="critical",
                        choices=("critical", "high", "medium", "low", "none"))
    parser.add_argument("--promptsonar-categories", default="security")
    parser.add_argument("--exit-on-findings", default="true", choices=("true", "false"))
    parser.add_argument("--pi-auditor-revision", default="unknown")
    parser.add_argument("--governance-failed", action="append", default=[])
    parser.add_argument("--scanner-error", action="store_true")
    parser.add_argument("--report-set", action="append", nargs=4, default=[],
                        metavar=("PROMPT", "PROMPTSONAR_JSON", "PROMPTSONAR_SARIF", "PI_AUDITOR_JSON"))
    args = parser.parse_args()
    args.categories = {item.strip().lower() for item in args.promptsonar_categories.split(",")
                       if item.strip()}
    if not args.categories:
        parser.error("--promptsonar-categories must contain at least one category")
    unknown = args.categories - PROMPTSONAR_CATEGORIES
    if unknown:
        parser.error(f"unknown PromptSonar categories: {', '.join(sorted(unknown))}; "
                     f"valid values: {', '.join(sorted(PROMPTSONAR_CATEGORIES))}")
    if not args.report_set:
        parser.error("at least one --report-set is required")
    return args


def main() -> int:
    args = parse_args()
    prompts: list[dict[str, Any]] = []
    published: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    documents: list[dict[str, Any]] = []
    source_reports: list[str] = []
    current_prompt = ""
    try:
        if args.scanner_error:
            for prompt, ps_json_text, _, auditor_json_text in args.report_set:
                prompts.append({"path": prompt, "result": "ERROR",
                                "promptsonar": report_summary(Path(ps_json_text), "promptsonar"),
                                "pi_auditor": report_summary(Path(auditor_json_text), "pi_auditor")})
            raise ValueError("one or more scanners had execution errors")
        for prompt, ps_json_text, ps_sarif_text, auditor_json_text in args.report_set:
            current_prompt = prompt
            ps_json_path = Path(ps_json_text)
            ps_sarif_path = Path(ps_sarif_text)
            auditor_json_path = Path(auditor_json_text)
            ps_report = read_json(ps_json_path)
            auditor_report = read_json(auditor_json_path)
            ps_summary = report_summary(ps_json_path, "promptsonar", ps_report)
            auditor_summary = report_summary(auditor_json_path, "pi_auditor", auditor_report)
            entry = {"path": prompt, "result": "ERROR", "promptsonar": ps_summary,
                     "pi_auditor": auditor_summary}
            prompts.append(entry)
            ps_sarif = read_json(ps_sarif_path)
            if ps_sarif.get("version") != SARIF_VERSION:
                raise ValueError(f"{ps_sarif_path}: expected SARIF {SARIF_VERSION}")
            pi_sarif = convert_pi_report(auditor_report)
            ps_sarif, ps_decisions, ps_gate = process_tool(
                ps_report, ps_sarif, "promptsonar", args.categories,
                args.fail_on)
            pi_sarif, pi_decisions, pi_gate = process_tool(
                auditor_report, pi_sarif, "pi-auditor", args.categories,
                args.fail_on)
            print_decisions(prompt, "PROMPTSONAR", ps_decisions)
            print()
            print_decisions(prompt, "PI-AUDITOR", pi_decisions)
            for tool_name, decisions in (("PromptSonar", ps_decisions),
                                         ("prompt-injection-auditor", pi_decisions)):
                for decision in decisions:
                    item = {"prompt": prompt, "tool": tool_name,
                            "rule_id": decision["rule_id"], "severity": decision["severity"],
                            "title": decision["title"], "reasons": decision["reasons"]}
                    (published if decision["included"] else excluded).append(item)
            governance = prompt in args.governance_failed
            entry["result"] = "BLOCK" if ps_gate + pi_gate or governance else "PASS"
            print(f"[SCAN-GATE] {prompt}: FAIL_ON={args.fail_on}, "
                  f"categorías PromptSonar={','.join(sorted(args.categories))}: "
                  f"PromptSonar={ps_gate}, pi-auditor={pi_gate}, "
                  f"governance={'BLOCK' if governance else 'PASS'} → {entry['result']}")
            documents.extend((ps_sarif, pi_sarif))
            source_reports.extend((ps_sarif_text, auditor_json_text))

        runs = merge_runs(documents)
        if not runs:
            raise ValueError("no SARIF runs were produced")
        if len(published) != sum(len(run["results"]) for run in runs):
            raise ValueError("published findings do not match consolidated SARIF results")
        unified = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs,
                   "properties": {"mergedBy": "DevSecops team", "sourceReports": source_reports}}
        write_json_atomically(args.output_sarif, unified)
        print(f"SARIF consolidado para Sonar: {args.output_sarif} "
              f"({sum(len(run['results']) for run in runs)} findings)")
        blocked = any(prompt["result"] == "BLOCK" for prompt in prompts)
        overall = "BLOCK" if blocked else "PASS"
        exit_code = 1 if blocked and args.exit_on_findings == "true" else 0
        summary = build_summary(args, prompts, overall, exit_code)
    except (OSError, ValueError, TypeError, KeyError) as error:
        args.output_sarif.unlink(missing_ok=True)
        published.clear()
        excluded.clear()
        print(f"ERROR: cannot consolidate scan reports: {error}", file=sys.stderr)
        summary = build_summary(args, prompts, "ERROR", 2,
                                f"{current_prompt}: {error}" if current_prompt else str(error))
        exit_code = 2
    write_json_atomically(args.output_summary, summary)
    print_summary(summary, args.output_summary, args.output_sarif, published, excluded)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
