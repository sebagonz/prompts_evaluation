#!/usr/bin/env python3
"""Convierte el JSON de prompt-injection-auditor a SARIF 2.1.0.

Uso:
  python3 pi_auditor_to_sarif.py entrada-pi-auditor.json --output salida.sarif

No depende de paquetes externos para que pueda ejecutarse dentro de la misma
imagen del POC y también fuera del contenedor con Python 3.9 o superior.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "prompt-injection-auditor"
LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}


class InputError(ValueError):
    """El reporte de entrada no tiene la estructura esperada."""


def as_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"'{field}' must be a non-empty string")
    return value.strip()


def finding_message(finding: Mapping[str, Any]) -> tuple[str, str]:
    """Devuelve una versión texto y otra Markdown del mensaje SARIF."""
    title = as_nonempty_string(finding.get("title"), "findings[].title")
    detail = finding.get("detail")
    fix = finding.get("fix")

    text_parts = [title]
    markdown_parts = [title]
    if isinstance(detail, str) and detail.strip():
        text_parts.append(detail.strip())
        markdown_parts.append(detail.strip())
    if isinstance(fix, str) and fix.strip():
        text_parts.append(f"Recommended fix: {fix.strip()}")
        markdown_parts.append(f"**Recommended fix:** {fix.strip()}")
    return "\n\n".join(text_parts), "\n\n".join(markdown_parts)


def result_locations(target: str, lines: Any) -> list[dict[str, Any]]:
    """Crea una ubicación por línea, si el auditor pudo determinarla."""
    if not isinstance(lines, Sequence) or isinstance(lines, (str, bytes)):
        return []

    locations: list[dict[str, Any]] = []
    seen_lines: set[int] = set()
    for line in lines:
        if not isinstance(line, int) or line < 1:
            continue
        if line in seen_lines:
            continue
        seen_lines.add(line)
        locations.append(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                    "region": {"startLine": line},
                }
            }
        )
    return locations


def convert(report: Mapping[str, Any]) -> dict[str, Any]:
    """Convierte un objeto JSON de pi-auditor en un log SARIF válido."""
    target = as_nonempty_string(report.get("target"), "target")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise InputError("'findings' must be an array")

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise InputError(f"findings[{index}] must be an object")

        rule_id = as_nonempty_string(finding.get("id"), "findings[].id")
        severity = str(finding.get("severity", "medium")).strip().lower()
        level = LEVELS.get(severity, "warning")
        text, markdown = finding_message(finding)
        detail = finding.get("detail")
        fix = finding.get("fix")

        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {
                    "text": detail.strip()
                    if isinstance(detail, str) and detail.strip()
                    else finding["title"]
                },
                "defaultConfiguration": {"level": level},
                "properties": {"piAuditorSeverity": severity},
            },
        )
        if isinstance(fix, str) and fix.strip():
            rules[rule_id]["help"] = {"text": fix.strip(), "markdown": fix.strip()}
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": text, "markdown": markdown},
            "properties": {
                "piAuditorSeverity": severity,
                "piAuditorTitle": finding["title"],
            },
        }
        locations = result_locations(target, finding.get("lines", []))
        if locations:
            result["locations"] = locations
        results.append(result)

    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": "https://github.com/screem500/prompt-injection-auditor",
        "rules": list(rules.values()),
    }
    tool = report.get("tool")
    if isinstance(tool, str) and tool.strip():
        driver["fullName"] = tool.strip()

    run: dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    timestamp = report.get("timestamp")
    if isinstance(timestamp, str) and timestamp.strip():
        run["invocations"] = [{"executionSuccessful": True, "endTimeUtc": timestamp}]

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Reporte JSON producido por pi_scan.py")
    parser.add_argument("--output", "-o", required=True, type=Path, help="Archivo SARIF a generar")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with args.input.open(encoding="utf-8") as source:
            report = json.load(source)
        if not isinstance(report, Mapping):
            raise InputError("the root JSON value must be an object")
        sarif = convert(report)
    except (OSError, json.JSONDecodeError, InputError) as error:
        print(f"ERROR: cannot convert '{args.input}': {error}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Escritura atómica: no deja un SARIF truncado si algo interrumpe el proceso.
        descriptor, temporary_name = tempfile.mkstemp(
            dir=args.output.parent, prefix=f".{args.output.name}.", suffix=".tmp"
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(sarif, output, indent=2, ensure_ascii=False)
            output.write("\n")
        os.replace(temporary_name, args.output)
    except OSError as error:
        print(f"ERROR: cannot write '{args.output}': {error}", file=sys.stderr)
        return 2

    print(f"SARIF written: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
