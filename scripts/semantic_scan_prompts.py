#!/usr/bin/env python3
"""Audita estáticamente prompts de sistema TXT mediante un juez LLM y LiteLLM.

Este archivo es el harness: prepara cada documento, llama al juez, valida su
JSON contra el esquema y las líneas originales, y escribe reportes. Nunca usa
el TXT auditado como mensaje de sistema de la llamada al juez.

Cada prompt tiene su propia tarea asíncrona y su propio contexto de mensajes.
El orquestador limita las llamadas simultáneas y es el único que escribe el
resumen compartido.
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


RuleId = Literal[
    "SEM-PI-01", "SEM-PI-02", "SEM-PI-03",
    "SEM-DISC-01", "SEM-DISC-02", "SEM-DISC-03",
    "SEM-AUTH-01", "SEM-AUTH-02", "SEM-AUTH-03", "SEM-AUTH-04",
    "SEM-OUT-01", "SEM-OUT-02", "SEM-KNOW-01", "SEM-RAG-01",
    "SEM-FACT-01", "SEM-FACT-02", "SEM-COST-01", "SEM-SUPPLY-01",
    "SEM-CONS-01",
]
Severity = Literal["low", "medium", "high", "critical"]
# Esta expresión solo reconoce dos formatos de clave conocidos. No es un
# detector general de secretos; evita reproducir esos formatos en el reporte.
SECRET_PATTERN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b")


# Modelos de salida: Pydantic valida tipos, campos permitidos y algunos límites.
# El juez propone los hallazgos; estas clases no verifican su interpretación.
def redact_sensitive_text(value: str) -> str:
    """Oculta patrones de claves reconocidos en campos narrativos."""
    return SECRET_PATTERN.sub("[REDACTED]", value)


class Finding(BaseModel):
    # strict evita convertir silenciosamente, por ejemplo, "12" en 12.
    model_config = ConfigDict(extra="forbid", strict=True)

    rule_id: RuleId
    severity: Severity
    title: str = Field(min_length=1)
    explanation: str = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    impact_conditions: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    evidence: str = Field(min_length=1)

    @field_validator("title", "explanation", "recommendation", "impact_conditions", "evidence")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("The field cannot be blank")
        return value


class AuditJudgement(BaseModel):
    # findings puede estar vacío: no se fuerza un hallazgo por archivo.
    model_config = ConfigDict(extra="forbid", strict=True)

    summary: str = Field(min_length=1)
    findings: list[Finding]
    limitations: list[str] = Field(min_length=1)

    @field_validator("summary")
    @classmethod
    def summary_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Summary cannot be blank")
        return value

    @field_validator("limitations")
    @classmethod
    def limitations_not_blank(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("Limitations cannot contain blank items")
        return values


class FindingReplacement(BaseModel):
    """Reemplazo de un único hallazgo cuya cita se rechazó."""
    model_config = ConfigDict(extra="forbid", strict=True)

    index: int = Field(ge=0)
    line_number: int = Field(ge=1)
    evidence: str = Field(min_length=1)


class FindingWithdrawal(BaseModel):
    """Retiro explícito de un candidato que no se puede fundamentar."""
    model_config = ConfigDict(extra="forbid", strict=True)

    index: int = Field(ge=0)
    reason: str = Field(min_length=1)


class CitationRepair(BaseModel):
    """Respuesta pequeña del reintento; no vuelve a generar el reporte entero."""
    model_config = ConfigDict(extra="forbid", strict=True)

    replacements: list[FindingReplacement]
    withdrawals: list[FindingWithdrawal]


def required_env(name: str) -> str:
    """Lee una variable obligatoria; falla antes de iniciar la corrida."""
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Falta {name}; configurá .env y ejecutá litellm/setup.py bootstrap")
    return value


def visible_txt_files(directory: Path, allow_empty: bool = False) -> list[Path]:
    """Lista los TXT visibles de forma estable, excluyendo enlaces y ocultos."""
    if directory.is_file():
        if directory.suffix.lower() != ".txt" or directory.is_symlink() or directory.name.startswith("."):
            if allow_empty:
                return []
            raise ValueError(f"No es un TXT visible: {directory}")
        return [directory]
    if not directory.is_dir():
        raise FileNotFoundError(f"No existe la carpeta de prompts: {directory}")
    files = sorted(
        path for path in directory.rglob("*")
        if path.is_file() and not path.is_symlink() and path.suffix.lower() == ".txt"
        and not any(part.startswith(".") for part in path.relative_to(directory).parts)
        and not any(parent.is_symlink() for parent in path.parents if parent != directory)
    )
    if not files and not allow_empty:
        raise FileNotFoundError(f"No hay archivos TXT visibles en {directory}")
    return files


def verify_finding_evidence(finding: Finding, lines: list[str]) -> dict:
    """Resuelve solo citas exactas y no ambiguas; devuelve el hallazgo publicable.

    Una cita de dos líneas se valida contra el texto contiguo al sustituir
    solamente el salto físico por un espacio. El reporte añade la línea final.
    Nunca se corrige por semejanza, traducción ni cambios de puntuación.
    """
    if SECRET_PATTERN.search(finding.evidence):
        raise ValueError(f"{finding.rule_id}: la cita contiene un posible secreto")
    if finding.line_number <= len(lines) and finding.evidence in lines[finding.line_number - 1]:
        return report_finding(finding)

    exact_lines = [index for index, line in enumerate(lines, 1) if finding.evidence in line]
    if len(exact_lines) == 1:
        record = report_finding(finding.model_copy(update={"line_number": exact_lines[0]}))
        record["model_line_number"] = finding.line_number
        record["citation_adjustment"] = "unique_exact_line"
        return record

    # Admitimos dos líneas contiguas solo si el texto aparece en un único par.
    # La evidencia queda normalizada al espacio usado para unir el salto.
    citation = finding.evidence.replace("\r\n", "\n").replace("\n", " ")
    spans = [
        index for index in range(len(lines) - 1)
        if citation in lines[index].rstrip() + " " + lines[index + 1].lstrip()
        and citation not in lines[index] and citation not in lines[index + 1]
    ]
    if not exact_lines and len(spans) == 1:
        start = spans[0] + 1
        record = report_finding(finding.model_copy(update={"line_number": start, "evidence": citation}))
        record["end_line_number"] = start + 1
        record["citation_adjustment"] = "adjacent_span"
        if start != finding.line_number:
            record["model_line_number"] = finding.line_number
        return record

    if finding.line_number > len(lines):
        raise ValueError(f"{finding.rule_id}: línea inexistente {finding.line_number}")
    raise ValueError(f"{finding.rule_id}: la cita no coincide con la línea {finding.line_number}")


def verify_evidence(judgement: AuditJudgement, lines: list[str]) -> None:
    """Contrasta todas las citas con las líneas originales del archivo."""
    for finding in judgement.findings:
        verify_finding_evidence(finding, lines)


def report_finding(finding: Finding) -> dict:
    """Prepara un hallazgo verificable para JSON, ocultando claves narrativas."""
    return {
        key: redact_sensitive_text(value) if isinstance(value, str) and key != "evidence" else value
        for key, value in finding.model_dump().items()
    }


class IncompleteAuditError(ValueError):
    """La respuesta falló; conserva solo citas verificadas para revisión."""

    def __init__(self, message: str, partial_findings: list[dict]):
        super().__init__(message)
        self.partial_findings = partial_findings


def save_json(path: Path, record: dict) -> None:
    """Escribe JSON primero en un temporal y luego reemplaza el destino."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def safe_error(error: Exception, secrets_to_hide: list[str]) -> str:
    """Reduce el detalle del error y redacta claves antes de publicarlo."""
    message = str(error)
    for secret in secrets_to_hide:
        if secret:
            message = message.replace(secret, "[REDACTED]")
    message = SECRET_PATTERN.sub("[REDACTED]", message)
    return f"{type(error).__name__}: {message[:400]}"


def provider_schema(schema: dict) -> dict:
    """Quita restricciones JSON Schema que algunos proveedores no aceptan.

    Pydantic conserva el esquema más estricto para validar la respuesta.
    """
    unsupported = {"minLength", "maxLength", "minimum", "maximum", "maxItems"}
    if isinstance(schema, dict):
        return {key: provider_schema(value) for key, value in schema.items() if key not in unsupported}
    if isinstance(schema, list):
        return [provider_schema(value) for value in schema]
    return schema


def validation_reason(error: ValidationError | ValueError) -> str:
    """Resume fallas de validación sin copiar la salida cruda del juez."""
    if isinstance(error, ValidationError):
        issues = []
        for issue in error.errors()[:4]:
            location = ".".join(str(part) for part in issue["loc"]) or "respuesta"
            issues.append(f"{location}: {issue['type']}")
        return ", ".join(issues)
    return str(error)


def citation_repair_message(
    judgement: AuditJudgement, invalid: dict[int, str], lines: list[str],
    schema: dict,
) -> str:
    """Pide corregir solo citas rechazadas, sin reenviar la respuesta cruda."""
    cases = []
    for index, reason in invalid.items():
        finding = judgement.findings[index]
        source_line = lines[finding.line_number - 1] if finding.line_number <= len(lines) else ""
        # El documento original sigue en el contexto del juez. Esta ayuda
        # repite la línea solo si es corta y no contiene patrones de claves.
        if not source_line or len(source_line) > 400 or SECRET_PATTERN.search(source_line):
            source_line = "[consultar línea numerada del documento original]"
        cases.append({
            "index": index, "rule_id": finding.rule_id,
            "line_number": finding.line_number, "error": reason,
            "source_line": source_line,
        })
    return (
        "Corrige SOLO los hallazgos rechazados a continuación. Los demás ya "
        "pasaron la validación y se conservarán sin volver a generarlos. "
        "Para cada index devuelve exactamente un replacement con line_number "
        "y evidence verificables, o un withdrawal con razón si el "
        "candidato no se fundamenta. No cites valores de claves. No agregues "
        "hallazgos nuevos ni reevalúes los válidos. Devuelve solo JSON conforme "
        "al esquema indicado.\nCASOS:\n"
        + json.dumps(cases, ensure_ascii=False)
        + "\nESQUEMA DE CORRECCIÓN:\n"
        + json.dumps(schema, ensure_ascii=False)
    )


def verify_repair_coverage(repair: CitationRepair, invalid_indices: set[int]) -> None:
    """Cada índice rechazado debe corregirse o retirarse una sola vez."""
    indices = [item.index for item in repair.replacements]
    indices.extend(item.index for item in repair.withdrawals)
    if len(indices) != len(set(indices)) or set(indices) != invalid_indices:
        raise ValueError("La corrección no cubre exactamente los hallazgos rechazados")


def format_elapsed(milliseconds: int) -> str:
    """Presenta un tiempo transcurrido como horas:minutos:segundos.milisegundos."""
    hours, remainder = divmod(milliseconds, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    seconds, milliseconds = divmod(remainder, 1_000)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{milliseconds:03d}"


def parse_rule_titles(rubric: str) -> dict[str, str]:
    """Obtiene ID y título de las cabeceras de regla de la rúbrica.

    La rúbrica es la fuente única de los títulos; así la tabla no mantiene
    otra lista que podría quedar desactualizada.
    """
    return dict(re.findall(r"(?m)^(SEM-[A-Z]+-\d{2}) — ([^\n.]+)\.", rubric))


def render_findings_table(
    report: dict, color: bool, width: int = 110,
    rule_titles: dict[str, str] | None = None,
) -> str:
    """Dibuja el resumen de consola; no modifica el reporte JSON."""
    rule_titles = rule_titles or {}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    severity_labels = {"critical": "CRÍTICA", "high": "ALTA", "medium": "MEDIA", "low": "BAJA"}
    severity_colors = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
    findings = [
        (result["file"], finding)
        for result in report["results"] if result["status"] == "REVIEW"
        for finding in result["findings"]
    ]
    partial_findings = [
        (result["file"], finding)
        for result in report["results"] if result["status"] == "ERROR"
        for finding in result.get("partial_findings", [])
    ]
    for group in (findings, partial_findings):
        group.sort(key=lambda item: (severity_order[item[1]["severity"]], item[0], item[1]["line_number"]))
    # Cada celda tiene un espacio a cada lado; hay seis bordes verticales.
    # La columna Regla necesita espacio para ID y título, ambos con ajuste.
    width = max(90, min(width, 150))
    content_width = width - 16
    prompt_width = min(30, max(20, round(content_width * 0.25)))
    rule_width = min(38, max(25, round(content_width * 0.34)))
    widths = [prompt_width, 5, rule_width, 10,
              content_width - prompt_width - 5 - rule_width - 10]

    def clean(value: object) -> str:
        # El título del juez y el nombre del archivo no pueden enviar controles
        # ANSI ni caracteres de dirección a la terminal.
        return " ".join(re.sub(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", " ", str(value)).split())

    def border(left: str, middle: str, right: str) -> str:
        return left + middle.join("─" * (size + 2) for size in widths) + right

    def row(values: list[object], severity: str | None = None) -> list[str]:
        # Cada celda puede ocupar varias líneas; el ancho sigue siendo fijo.
        wrapped = [textwrap.wrap(clean(value), size, break_on_hyphens=False) or [""] for value, size in zip(values, widths)]
        lines = []
        for index in range(max(map(len, wrapped))):
            cells = [(parts[index] if index < len(parts) else "").ljust(size) for parts, size in zip(wrapped, widths)]
            if color and severity and index == 0:
                cells[3] = severity_colors[severity] + cells[3] + "\033[0m"
            lines.append("│ " + " │ ".join(cells) + " │")
        return lines

    lines = ["", "Hallazgos por archivo (severidad propuesta)", border("┌", "┬", "┐")]
    lines.extend(row(["Prompt", "Línea", "Regla", "Criticidad", "Hallazgo"]))
    lines.append(border("├", "┼", "┤"))
    if findings:
        for index, (filename, finding) in enumerate(findings):
            if index:
                lines.append(border("├", "┼", "┤"))
            rule_id = finding["rule_id"]
            rule_label = f"{rule_id} — {rule_titles[rule_id]}" if rule_id in rule_titles else rule_id
            line_label = (
                f"{finding['line_number']}–{finding['end_line_number']}"
                if "end_line_number" in finding else finding["line_number"]
            )
            lines.extend(row([
                filename, line_label, rule_label,
                severity_labels[finding["severity"]], finding["title"],
            ], finding["severity"]))
    else:
        lines.extend(row(["Sin hallazgos validados", "", "", "", ""]))
    lines.append(border("└", "┴", "┘"))
    counts = {severity: sum(finding["severity"] == severity for _, finding in findings) for severity in severity_order}
    status_counts = report["counts"]
    lines.append(
        f"Total {len(findings)} | Crítica {counts['critical']} | Alta {counts['high']} | "
        f"Media {counts['medium']} | Baja {counts['low']} | "
        f"Sin hallazgos {status_counts['NO_FINDINGS']} | Errores {status_counts['ERROR']}"
    )
    if partial_findings:
        lines.extend(["", "Hallazgos parciales de archivos con ERROR (auditoría incompleta)", border("┌", "┬", "┐")])
        lines.extend(row(["Prompt", "Línea", "Regla", "Criticidad", "Hallazgo"]))
        lines.append(border("├", "┼", "┤"))
        for index, (filename, finding) in enumerate(partial_findings):
            if index:
                lines.append(border("├", "┼", "┤"))
            rule_id = finding["rule_id"]
            rule_label = f"{rule_id} — {rule_titles[rule_id]}" if rule_id in rule_titles else rule_id
            line_label = (
                f"{finding['line_number']}–{finding['end_line_number']}"
                if "end_line_number" in finding else finding["line_number"]
            )
            lines.extend(row([
                filename, line_label, rule_label,
                severity_labels[finding["severity"]], finding["title"],
            ], finding["severity"]))
        lines.append(border("└", "┴", "┘"))
        lines.append(f"Parciales {len(partial_findings)} | Revisar el archivo con ERROR; no cuenta como auditoría completa.")
    errors = [result for result in report["results"] if result["status"] == "ERROR"]
    if errors:
        # El total de errores por sí solo no indica qué archivo quedó sin
        # auditar. Repetimos el diagnóstico al final para que sea visible
        # junto a las tablas aunque las tareas hayan terminado en otro orden.
        lines.extend(["", "Archivos con ERROR (auditoría incompleta)"])
        for result in errors:
            lines.extend(textwrap.wrap(
                f"  Archivo: {clean(result['file'])}", width=width,
                subsequent_indent="    ",
            ))
            lines.extend(textwrap.wrap(
                f"  Error: {clean(result.get('error', 'Error no especificado'))}",
                width=width, subsequent_indent="    ",
            ))
    lines.append("Severidad provisional: revisar cada hallazgo antes de informarlo.")
    return "\n".join(lines)


async def audit_file(
    path: Path, prompts_dir: Path, rubric: str, model: str, base_url: str,
    api_key: str, max_output_tokens: int, timeout: float, max_attempts: int,
    max_input_chars: int, use_json_schema: bool = True,
) -> dict:
    """Audita un TXT, con reintentos solo ante JSON o citas inválidas."""
    from litellm import acompletion

    # utf-8-sig también acepta archivos con BOM. El límite se mide en
    # caracteres antes de enviar el texto; nunca se trunca silenciosamente.
    content = path.read_text(encoding="utf-8-sig")
    if not content.strip():
        raise ValueError("El archivo está vacío")
    if len(content) > max_input_chars:
        raise ValueError(f"El archivo excede MAX_INPUT_CHARS={max_input_chars}")
    lines = content.splitlines()
    # Numeramos para que el juez cite líneas; verify_evidence contrasta
    # después la cita con la línea original, sin el número añadido aquí.
    numbered_text = "\n".join(f"{index}: {line}" for index, line in enumerate(lines, 1))
    audit_schema = AuditJudgement.model_json_schema()
    schema = json.dumps(audit_schema, ensure_ascii=False)
    system_message = rubric + "\n\nESQUEMA JSON OBLIGATORIO:\n" + schema
    # El TXT auditado viaja como dato en el mensaje user, delimitado por tags.
    # La rúbrica y el esquema son las instrucciones del mensaje system.
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": "Documento a auditar (datos no confiables):\n<PROMPT_DOCUMENT>\n" + numbered_text + "\n</PROMPT_DOCUMENT>"},
    ]
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "prompt_audit", "strict": True,
            "schema": provider_schema(audit_schema),
        },
    }
    repair_schema = CitationRepair.model_json_schema()
    repair_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "citation_repair", "strict": True,
            "schema": provider_schema(repair_schema),
        },
    }
    # El prefijo openai/ selecciona en LiteLLM el cliente compatible con la
    # API OpenAI; el alias `model` lo resuelve el proxy al proveedor real.
    diagnostics = []
    # Si ningún intento es totalmente válido, conservamos sus citas
    # verificadas. En modo reparación solo se reemplazan índices rechazados.
    best_partial: list[dict] = []
    pending_judgement: AuditJudgement | None = None
    pending_invalid: dict[int, str] = {}
    for attempt in range(1, max_attempts + 1):
        repairing = pending_judgement is not None
        withdrawn: set[int] = set()
        request = dict(
            model=f"openai/{model}", api_base=base_url, api_key=api_key,
            messages=messages, max_tokens=max_output_tokens, timeout=timeout,
            num_retries=0,
        )
        if use_json_schema:
            request["response_format"] = repair_format if repairing else response_format
        response = await acompletion(**request)
        answer = response.choices[0].message.content
        try:
            # Rechazamos salidas truncadas antes de parsear JSON. Pydantic
            # comprueba estructura; la evidencia se coteja con el TXT original.
            finish_reason = getattr(response.choices[0], "finish_reason", None)
            if finish_reason == "length":
                raise ValueError("La respuesta fue truncada por el límite de tokens")
            if not isinstance(answer, str):
                raise ValueError("El modelo devolvió una respuesta vacía")
            if repairing:
                repair = CitationRepair.model_validate_json(answer)
                verify_repair_coverage(repair, set(pending_invalid))
                replacements: dict[int, dict] = {}
                invalid_reasons: list[str] = []
                for item in repair.replacements:
                    original = pending_judgement.findings[item.index]
                    corrected = Finding.model_validate({
                        **original.model_dump(), "line_number": item.line_number,
                        "evidence": item.evidence,
                    })
                    try:
                        corrected_record = verify_finding_evidence(corrected, lines)
                    except ValueError as citation_error:
                        invalid_reasons.append(str(citation_error))
                    else:
                        replacements[item.index] = corrected_record
                withdrawn = {item.index for item in repair.withdrawals}
                final_findings = [
                    replacements[index] if index in pending_invalid else verify_finding_evidence(finding, lines)
                    for index, finding in enumerate(pending_judgement.findings)
                    if index not in withdrawn and (index not in pending_invalid or index in replacements)
                ]
                partial = final_findings
                if len(partial) > len(best_partial):
                    best_partial = partial
                if invalid_reasons:
                    raise ValueError(
                        f"{invalid_reasons[0]} (correcciones inválidas: {len(invalid_reasons)})"
                    )
                judgement = pending_judgement
                limitations = list(judgement.limitations)
                if withdrawn:
                    limitations.append(
                        f"Se retiraron {len(withdrawn)} candidatos sin cita fundamentable durante la corrección."
                    )
            else:
                judgement = AuditJudgement.model_validate_json(answer)
                verified: list[dict] = []
                invalid: dict[int, str] = {}
                for index, finding in enumerate(judgement.findings):
                    try:
                        verified_record = verify_finding_evidence(finding, lines)
                    except ValueError as citation_error:
                        invalid[index] = str(citation_error)
                    else:
                        verified.append(verified_record)
                if invalid:
                    if len(verified) > len(best_partial):
                        best_partial = verified
                    if attempt < max_attempts:
                        pending_judgement = judgement
                        pending_invalid = invalid
                        messages.append({
                            "role": "user",
                            "content": citation_repair_message(
                                judgement, invalid, lines, repair_schema,
                            ),
                        })
                    raise ValueError(
                        f"{next(iter(invalid.values()))} (citas inválidas: {len(invalid)})"
                    )
                if not judgement.findings and best_partial:
                    # Un reintento vacío no borra evidencia de uno anterior.
                    raise ValueError(
                        "El reintento omitió todos los hallazgos con citas verificables del intento anterior"
                    )
                final_findings = verified
                limitations = judgement.limitations
        except (ValidationError, ValueError) as error:
            # Nunca reenviamos la respuesta cruda ni sus posibles secretos.
            reason = validation_reason(error)
            diagnostics.append(f"intento {attempt}: {reason}; finish_reason={finish_reason}; caracteres={len(answer) if isinstance(answer, str) else 0}")
            if attempt < max_attempts:
                if pending_judgement is None:
                    messages.append({"role": "user", "content": f"La respuesta anterior no cumplió la validación ({reason}). Vuelve a evaluar el mismo documento y devuelve solo JSON válido con citas verificables."})
                elif repairing:
                    messages.append({"role": "user", "content": f"La corrección anterior no validó ({reason}). Corrige solo los índices rechazados indicados antes y devuelve únicamente el JSON del esquema de corrección."})
                continue
            break
        usage = getattr(response, "usage", None)
        # Una respuesta válida se guarda como propuesta para revisión humana.
        # Las citas ya se validaron; el resto de textos se redacta al guardar.
        summary = judgement.summary
        if withdrawn:
            # El resumen original podría seguir describiendo un candidato que
            # el propio juez retiró; usamos una síntesis neutra y verificable.
            withdrawn_label = "candidato retirado" if len(withdrawn) == 1 else "candidatos retirados"
            summary = (
                f"Revisión estática con {len(final_findings)} hallazgos propuestos; "
                f"{len(withdrawn)} {withdrawn_label} al corregir citas."
            )
        return {
            "file": path.relative_to(prompts_dir).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "status": "REVIEW" if final_findings else "NO_FINDINGS",
            "review_required": True,
            "model": model,
            "summary": redact_sensitive_text(summary),
            "findings": final_findings,
            "limitations": [redact_sensitive_text(value) for value in limitations],
            "attempts": attempt,
            "usage": {
                "prompt_tokens": getattr(usage, "prompt_tokens", None),
                "completion_tokens": getattr(usage, "completion_tokens", None),
                "total_tokens": getattr(usage, "total_tokens", None),
            },
        }
    raise IncompleteAuditError(
        f"El modelo no produjo un reporte válido después de {max_attempts} intentos: {' | '.join(diagnostics)}",
        best_partial,
    )


async def run_prompt_agent(
    index: int, path: Path, total: int, semaphore: asyncio.Semaphore,
    prompts_dir: Path, rubric: str, model: str, base_url: str, api_key: str,
    max_output_tokens: int, timeout: float, max_attempts: int,
    max_input_chars: int, use_json_schema: bool,
) -> tuple[int, dict]:
    """Ejecuta un agente aislado por prompt y devuelve su resultado al orquestador.

    El semáforo limita las llamadas concurrentes al proxy. Cada invocación de
    audit_file crea mensajes y reintentos propios; ningún agente ve los TXT ni
    las respuestas de los demás.
    """
    async with semaphore:
        relative = path.relative_to(prompts_dir).as_posix()
        start = time.monotonic()
        started_at = datetime.now(timezone.utc)
        print(
            f"[{index + 1}/{total}] {relative}: inicio "
            f"{started_at:%Y-%m-%d %H:%M:%S} UTC",
            flush=True,
        )
        try:
            record = await audit_file(
                path, prompts_dir, rubric, model, base_url, api_key,
                max_output_tokens, timeout, max_attempts, max_input_chars,
                use_json_schema,
            )
        except Exception as error:
            # El error de un agente queda aislado y no cancela a los demás.
            try:
                file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                file_hash = None
            record = {
                "file": relative,
                "sha256": file_hash,
                "status": "ERROR", "review_required": True,
                "model": model, "summary": "Auditoría incompleta",
                "findings": [], "limitations": [],
                "partial_findings": error.partial_findings if isinstance(error, IncompleteAuditError) else [],
                "error": safe_error(error, [api_key]),
            }
        record["audited_at"] = datetime.now(timezone.utc).isoformat()
        record["started_at"] = started_at.isoformat()
        record["duration_ms"] = round((time.monotonic() - start) * 1000)
        return index, record


async def audit_prompts(report: dict) -> None:
    """Orquesta agentes por prompt y publica reportes acumulados."""
    started_monotonic = time.monotonic()
    started = datetime.now(timezone.utc)
    prompts_dir = Path(os.getenv("PROMPTS_DIR", "/workspace/prompts"))
    reports_dir = Path(os.getenv("REPORTS_DIR", "/workspace/reports")) / "prompt_audit"
    files = visible_txt_files(prompts_dir, allow_empty=True)
    if not files:
        report["status"] = "NOT_APPLICABLE"
        print("SEMANTIC: sin TXT elegibles; NOT_APPLICABLE", flush=True)
        return
    if prompts_dir.is_file():
        prompts_dir = prompts_dir.parent
    # Se exige una clave virtual; nunca se usa la clave maestra del proxy.
    model = required_env("MODEL_NAME")
    base_url = required_env("LITELLM_BASE_URL").rstrip("/")
    api_key = required_env("LITELLM_API_KEY")
    rubric_path = Path(os.getenv("AUDIT_RUBRIC_PATH", "/workspace/audit_rubric.md"))
    rubric = rubric_path.read_text(encoding="utf-8")
    if not rubric.strip():
        raise ValueError("La rúbrica de auditoría está vacía")
    max_output_tokens = int(os.getenv("MAX_OUTPUT_TOKENS", "6000"))
    timeout = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "120"))
    max_attempts = int(os.getenv("MAX_ATTEMPTS", "2"))
    max_parallel_prompts = int(os.getenv("MAX_PARALLEL_PROMPTS", "4"))
    max_input_chars = int(os.getenv("MAX_INPUT_CHARS", "30000"))
    use_json_schema = os.getenv("USE_JSON_SCHEMA", "1") == "1"
    if min(max_output_tokens, max_attempts, max_parallel_prompts, max_input_chars) < 1 or timeout <= 0:
        raise ValueError("Los límites configurados deben ser positivos")
    run_id = report["run_id"]
    run_dir = reports_dir / "runs" / run_id
    report.update(model=model, rubric_sha256=hashlib.sha256(rubric.encode("utf-8")).hexdigest())
    print(
        f"Auditando {len(files)} archivos TXT con {model} "
        f"(hasta {max_parallel_prompts} agentes en paralelo)",
        flush=True,
    )
    print(f"Inicio de la corrida: {started:%Y-%m-%d %H:%M:%S} UTC", flush=True)
    semaphore = asyncio.Semaphore(max_parallel_prompts)
    # Una tarea independiente por prompt. Solo los primeros N agentes entran
    # al semáforo; el resto espera su turno sin llamar todavía al proveedor.
    tasks = [
        asyncio.create_task(run_prompt_agent(
            index, path, len(files), semaphore, prompts_dir, rubric, model,
            base_url, api_key, max_output_tokens, timeout, max_attempts,
            max_input_chars, use_json_schema,
        ))
        for index, path in enumerate(files)
    ]
    completed: list[dict | None] = [None] * len(files)
    # El orquestador recibe resultados al completarse, pero conserva el orden
    # original de archivos en los JSON y en la tabla final.
    for task in asyncio.as_completed(tasks):
        index, record = await task
        relative = record["file"]
        record["schema_version"] = 1
        record["run_id"] = run_id
        record["method"] = "static_semantic_prompt_review"
        record["rubric_sha256"] = report["rubric_sha256"]
        # Solo el orquestador escribe archivos compartidos: no hay dos tareas
        # modificando summary.json al mismo tiempo.
        save_json(run_dir / f"{relative}.json", record)
        completed[index] = record
        report["results"] = [item for item in completed if item is not None]
        elapsed_ms = round((time.monotonic() - started_monotonic) * 1000)
        finished_at = datetime.fromisoformat(record["audited_at"])
        if record["status"] == "ERROR":
            print(
                f"[{index + 1}/{len(files)}] {relative}: ERROR — {record['error']}",
                flush=True,
            )
            if record.get("partial_findings"):
                print(
                    f"  {len(record['partial_findings'])} hallazgo(s) parcial(es) con cita verificable; "
                    "la auditoría sigue incompleta.",
                    flush=True,
                )
            if "Connection error" in record["error"]:
                print("  Detalle de conexión del proxy: docker compose logs --tail=100 litellm", flush=True)
        else:
            print(
                f"[{index + 1}/{len(files)}] {relative}: {record['status']} "
                f"({len(record['findings'])} hallazgos)",
                flush=True,
            )
        print(
            f"  Fin: {finished_at:%Y-%m-%d %H:%M:%S} UTC | "
            f"Tiempo del prompt: {format_elapsed(record['duration_ms'])} | "
            f"Transcurrido de la corrida: {format_elapsed(elapsed_ms)}",
            flush=True,
        )
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["duration_ms"] = elapsed_ms
        report["counts"] = {
            status: sum(item["status"] == status for item in report["results"])
            for status in ("REVIEW", "NO_FINDINGS", "ERROR")
        }
        save_json(run_dir / "summary.json", report)
        save_json(reports_dir / "summary.json", report)
    color = os.getenv("FORCE_COLOR") == "1" or (not os.getenv("NO_COLOR") and sys.stdout.isatty())
    print(render_findings_table(
        report, color, shutil.get_terminal_size((110, 24)).columns,
        parse_rule_titles(rubric),
    ), flush=True)
    print(
        f"Fin de la corrida: "
        f"{datetime.fromisoformat(report['finished_at']):%Y-%m-%d %H:%M:%S} UTC",
        flush=True,
    )
    print(f"Tiempo total: {format_elapsed(report['duration_ms'])}", flush=True)
    print(f"Reporte: {reports_dir / 'summary.json'}", flush=True)
    if report["counts"]["ERROR"]:
        # 2: auditoría incompleta. 1: hallazgos si el pipeline lo configuró.
        raise SystemExit(2)
    if os.getenv("FAIL_ON_FINDINGS", "0") == "1" and report["counts"]["REVIEW"]:
        raise SystemExit(1)


async def main() -> None:
    """Publica el estado de la corrida desde el inicio, incluso si falla el setup."""
    started = datetime.now(timezone.utc)
    reports_dir = Path(os.getenv("REPORTS_DIR", "/workspace/reports")) / "prompt_audit"
    report = {
        "run_id": started.strftime("%Y%m%dT%H%M%S%fZ"),
        "method": "static_semantic_prompt_review",
        "started_at": started.isoformat(),
        "prompt_directory": os.getenv("PROMPTS_DIR", "/workspace/prompts"),
        "status": "RUNNING", "results": [],
        "counts": {status: 0 for status in ("REVIEW", "NO_FINDINGS", "ERROR")},
    }
    paths = (reports_dir / "summary.json", reports_dir / "runs" / report["run_id"] / "summary.json")
    for path in paths:
        save_json(path, report)
    code = 0
    try:
        await audit_prompts(report)
    except SystemExit as error:
        code = int(error.code or 0)
    except Exception as error:
        code = 2
        report["error"] = safe_error(error, [os.getenv("LITELLM_API_KEY", "")])
        print(f"SEMANTIC ERROR: {report['error']}", flush=True)
    if report["status"] != "NOT_APPLICABLE":
        report["status"] = "ERROR" if code == 2 else "COMPLETE"
    report["exit_code"] = code
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    for path in paths:
        save_json(path, report)
    if code:
        raise SystemExit(code)


def cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--defer-exit", action="store_true",
                        help="Deja que el consolidador devuelva el código final; conserva errores en el JSON")
    parser.add_argument("target", nargs="?", help="Carpeta o TXT; por defecto PROMPTS_DIR")
    args = parser.parse_args()
    if args.target is not None:
        os.environ["PROMPTS_DIR"] = args.target
    if args.defer_exit:
        os.environ["FAIL_ON_FINDINGS"] = "0"
    try:
        asyncio.run(main())
    except SystemExit as error:
        return 0 if args.defer_exit else int(error.code or 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
