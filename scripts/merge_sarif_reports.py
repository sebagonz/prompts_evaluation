#!/usr/bin/env python3
"""Consolida varios reportes SARIF 2.1.0 en un único archivo.

Los runs se agrupan por herramienta para obtener, normalmente, un run de
PromptSonar y otro de prompt-injection-auditor. Cada resultado conserva su URI
y ubicación original, por lo que SonarQube puede asociarlo al prompt correcto.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", "-i", action="append", required=True, type=Path)
    parser.add_argument("--output", "-o", required=True, type=Path)
    return parser.parse_args()


def read_sarif(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as report_file:
            document = json.load(report_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read '{path}': {error}") from error

    if not isinstance(document, dict) or document.get("version") != SARIF_VERSION:
        raise ValueError(f"'{path}' is not a SARIF {SARIF_VERSION} document")
    if not isinstance(document.get("runs"), list):
        raise ValueError(f"'{path}' does not contain a runs array")
    return document


def tool_key(run: dict[str, Any]) -> tuple[str, str, str]:
    driver = run.get("tool", {}).get("driver", {})
    if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
        raise ValueError("a SARIF run does not contain tool.driver.name")
    return (
        driver["name"],
        str(driver.get("version", "")),
        str(driver.get("informationUri", "")),
    )


def merge_runs(documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    rule_ids: dict[tuple[str, str, str], set[str]] = {}

    for document in documents:
        for source_run in document["runs"]:
            if not isinstance(source_run, dict):
                raise ValueError("a SARIF run is not an object")
            key = tool_key(source_run)
            if key not in merged:
                destination = copy.deepcopy(source_run)
                destination["results"] = []
                driver = destination["tool"]["driver"]
                rules = driver.get("rules", [])
                if not isinstance(rules, list):
                    rules = []
                driver["rules"] = rules
                merged[key] = destination
                rule_ids[key] = {
                    rule["id"] for rule in rules
                    if isinstance(rule, dict) and isinstance(rule.get("id"), str)
                }

            destination = merged[key]
            destination["results"].extend(copy.deepcopy(source_run.get("results", [])))
            destination_driver = destination["tool"]["driver"]
            for rule in source_run.get("tool", {}).get("driver", {}).get("rules", []):
                if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                    continue
                if rule["id"] not in rule_ids[key]:
                    destination_driver["rules"].append(copy.deepcopy(rule))
                    rule_ids[key].add(rule["id"])

    return list(merged.values())


def write_atomically(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output_file:
            json.dump(document, output_file, indent=2, ensure_ascii=False)
            output_file.write("\n")
        os.replace(temporary_name, path)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def main() -> int:
    args = parse_arguments()
    documents = [read_sarif(path) for path in args.input]
    runs = merge_runs(documents)
    if not runs:
        raise ValueError("no runs were found in the supplied SARIF reports")

    output = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": runs,
        "properties": {
            "mergedBy": "DevSecops team",
            "sourceReports": [str(path) for path in args.input],
        },
    }
    write_atomically(args.output, output)
    print(f"Unified SARIF written: {args.output} ({len(runs)} tool runs)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR: cannot merge SARIF reports: {error}", file=sys.stderr)
        raise SystemExit(2)
