#!/usr/bin/env python3
"""Construye un resumen de ejecución a partir de reportes PromptSonar y pi-auditor."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


def empty_counts() -> dict[str, int]:
    return {severity: 0 for severity in SEVERITIES}


def read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with path.open(encoding="utf-8") as report_file:
            data = json.load(report_file)
    except (OSError, json.JSONDecodeError) as error:
        return None, str(error)
    if not isinstance(data, dict):
        return None, "root JSON value is not an object"
    return data, None


def counts_from_findings(findings: Any, severity_key: str) -> dict[str, int]:
    counts = Counter()
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get(severity_key, "unknown")).strip().lower()
            counts[severity if severity in SEVERITIES else "unknown"] += 1
    result = empty_counts()
    result.update(counts)
    return result


def report_summary(path_text: str, tool: str) -> dict[str, Any]:
    path = Path(path_text)
    report, error = read_json(path)
    if error:
        return {
            "report": path_text,
            "available": False,
            "error": error,
            "findings": empty_counts(),
            "total_findings": 0,
        }

    findings = counts_from_findings(report.get("findings"), "severity")
    summary: dict[str, Any] = {
        "report": path_text,
        "available": True,
        "findings": findings,
        "total_findings": sum(findings.values()),
    }
    if tool == "promptsonar":
        summary["version"] = report.get("version", "unknown")
        summary["overall_risk"] = report.get("executive_summary", {}).get("overall_risk", "unknown")
    else:
        summary["tool"] = report.get("tool", "prompt-injection-auditor")
        summary["risk_score"] = report.get("risk_score")
        summary["verdict"] = report.get("verdict", "unknown")
    return summary


def add_counts(total: Counter[str], counts: dict[str, int]) -> None:
    for severity, value in counts.items():
        total[severity] += value


def format_counts(counts: dict[str, int]) -> str:
    return " ".join(f"{severity.title()}={counts.get(severity, 0)}" for severity in SEVERITIES[:4])


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--promptsonar-fail-on", required=True)
    parser.add_argument("--exit-on-findings", required=True, choices=("true", "false"))
    parser.add_argument("--pi-auditor-revision", default="unknown")
    parser.add_argument("--overall-result", required=True, choices=("PASS", "BLOCK", "ERROR"))
    parser.add_argument("--expected-exit-code", required=True, type=int)
    parser.add_argument(
        "--report-pair",
        action="append",
        nargs=4,
        metavar=("PROMPT", "PROMPTSONAR_JSON", "PI_AUDITOR_JSON", "RESULT"),
        default=[],
        help="Puede repetirse; RESULT debe ser PASS, BLOCK o ERROR.",
    )
    return parser.parse_args()


def write_json_atomically(output: Path, document: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent, prefix=f".{output.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output_file:
            json.dump(document, output_file, indent=2, ensure_ascii=False)
            output_file.write("\n")
        os.replace(temporary_name, output)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def main() -> int:
    args = parse_arguments()
    promptsonar_total = Counter(empty_counts())
    auditor_total = Counter(empty_counts())
    prompts: list[dict[str, Any]] = []

    for prompt, promptsonar_path, auditor_path, result in args.report_pair:
        promptsonar = report_summary(promptsonar_path, "promptsonar")
        auditor = report_summary(auditor_path, "pi_auditor")
        add_counts(promptsonar_total, promptsonar["findings"])
        add_counts(auditor_total, auditor["findings"])
        prompts.append(
            {
                "path": prompt,
                "result": result,
                "promptsonar": promptsonar,
                "pi_auditor": auditor,
            }
        )

    document = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "policy": {
            "promptsonar_fail_on": args.promptsonar_fail_on,
            "exit_on_findings": args.exit_on_findings == "true",
        },
        "tools": {"pi_auditor_revision": args.pi_auditor_revision},
        "prompts": prompts,
        "totals": {
            "promptsonar": dict(promptsonar_total),
            "pi_auditor": dict(auditor_total),
        },
        "overall_result": args.overall_result,
        "expected_exit_code": args.expected_exit_code,
    }
    write_json_atomically(args.output, document)

    print("========================================")
    print(" EXECUTION SUMMARY BY PROMPT")
    print("========================================")
    for prompt in prompts:
        print(f"PROMPT: {prompt['path']}")
        print(f"  PROMPTSONAR : {format_counts(prompt['promptsonar']['findings'])}")
        print(f"  PI-AUDITOR  : {format_counts(prompt['pi_auditor']['findings'])}")
        print(f"  RESULT      : {prompt['result']}")
    print("----------------------------------------")
    print(f"TOTAL PROMPTSONAR: {format_counts(dict(promptsonar_total))}")
    print(f"TOTAL PI-AUDITOR : {format_counts(dict(auditor_total))}")
    print(f"OVERALL RESULT   : {args.overall_result}")
    print(f"SUMMARY JSON     : {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR: cannot build execution summary: {error}", file=sys.stderr)
        raise SystemExit(2)
