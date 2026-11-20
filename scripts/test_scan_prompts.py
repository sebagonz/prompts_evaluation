"""Tests for the report contract and literal source evidence."""

import asyncio
import io
import json
import os
import re
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from semantic_scan_prompts import (
    AuditJudgement, Finding, audit_file, main, parse_rule_titles,
    render_findings_table, verify_evidence, verify_finding_evidence,
)


def response(payload: dict):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))],
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=50, total_tokens=150),
    )


class AuditContractTests(unittest.TestCase):
    def test_rubric_rules_match_schema_and_have_examples(self):
        rubric = (Path(__file__).parent / "audit_rubric.md").read_text(encoding="utf-8")
        cards = re.findall(
            r"(?ms)^(SEM-[A-Z]+-\d\d) — .*?(?=^SEM-[A-Z]+-\d\d — |^EXCLUSIONES$)",
            rubric,
        )
        self.assertEqual(set(cards), set(AuditJudgement.model_json_schema()["$defs"]["Finding"]["properties"]["rule_id"]["enum"]))
        self.assertEqual(len(cards), len(set(cards)))
        titles = parse_rule_titles(rubric)
        self.assertEqual(set(titles), set(cards))
        self.assertEqual(titles["SEM-PI-01"], "Escalada desde el usuario")
        for card in re.findall(
            r"(?ms)^SEM-[A-Z]+-\d\d — .*?(?=^SEM-[A-Z]+-\d\d — |^EXCLUSIONES$)",
            rubric,
        ):
            self.assertIn("Ejemplo:", card)
            self.assertIn("Contraejemplo:", card)

    def test_findings_table_shows_file_and_severity_with_optional_color(self):
        report = {
            "results": [{
                "file": "carpeta/vulnerable_prompt.txt", "status": "REVIEW",
                "findings": [{
                    "line_number": 12, "rule_id": "SEM-PI-01", "severity": "critical",
                    "title": "Título\x1b[2J con control de terminal",
                }],
            }],
            "counts": {"REVIEW": 1, "NO_FINDINGS": 0, "ERROR": 0},
        }
        labels = {"SEM-PI-01": "Escalada desde el usuario"}
        plain = render_findings_table(report, color=False, width=90, rule_titles=labels)
        colored = render_findings_table(report, color=True, width=90, rule_titles=labels)
        self.assertIn("carpeta/vulnerable_", plain)
        self.assertIn("CRÍTICA", plain)
        self.assertIn("SEM-PI-01", plain)
        self.assertIn("Escalada", plain)
        self.assertIn("usuario", plain)
        self.assertNotIn("\x1b", plain)
        self.assertIn("\x1b[1;31mCRÍTICA", colored)
        self.assertNotIn("\x1b[2J", colored)

    def test_litellm_sdk_calls_openai_compatible_gateway(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request_body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((self.path, self.headers.get("Authorization"), request_body))
                result = {
                    "id": "chatcmpl-local-test", "object": "chat.completion",
                    "created": 1, "model": "audit-anthropic",
                    "choices": [{"index": 0, "finish_reason": "stop", "message": {
                        "role": "assistant", "content": json.dumps({
                            "summary": "No hay hallazgos explícitos.", "findings": [],
                            "limitations": ["No se probó la aplicación."],
                        }),
                    }}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
                }
                encoded = json.dumps(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                prompt = root / "system.txt"
                prompt.write_text("Sé claro.\n", encoding="utf-8")
                result = asyncio.run(audit_file(
                    prompt, root, "Rúbrica", "audit-anthropic",
                    f"http://127.0.0.1:{server.server_port}/v1",
                    "sk-test-only", 3000, 20, 1, 30000,
                ))
            self.assertEqual(result["status"], "NO_FINDINGS")
            self.assertEqual(seen[0][0], "/v1/chat/completions")
            self.assertEqual(seen[0][1], "Bearer sk-test-only")
            self.assertEqual(seen[0][2]["model"], "audit-anthropic")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_writes_per_file_and_summary_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompts = root / "prompts"
            prompts.mkdir()
            (prompts / "system.txt").write_text("Respondé con claridad.\n", encoding="utf-8")
            rubric = root / "rubric.md"
            rubric.write_text("Rúbrica de prueba", encoding="utf-8")

            async def fake_completion(**kwargs):
                return response({
                    "summary": "No se encontraron debilidades explícitas.",
                    "findings": [],
                    "limitations": ["No se probó la aplicación."],
                })

            settings = {
                "MODEL_NAME": "audit-anthropic", "LITELLM_BASE_URL": "http://litellm:4000/v1",
                "LITELLM_API_KEY": "sk-test-only", "PROMPTS_DIR": str(prompts),
                "REPORTS_DIR": str(root / "reports"), "AUDIT_RUBRIC_PATH": str(rubric),
                "MAX_ATTEMPTS": "1", "MAX_INPUT_CHARS": "100",
            }
            with patch.dict(os.environ, settings), patch("litellm.acompletion", new=fake_completion):
                asyncio.run(main())
            directory_out = root / "reports" / "prompt_audit"
            summary = json.loads((directory_out / "summary.json").read_text())
            item = json.loads((directory_out / "runs" / summary["run_id"] / "system.txt.json").read_text())
            self.assertEqual(item["status"], "NO_FINDINGS")
            self.assertEqual(item["schema_version"], 1)
            self.assertEqual(item["run_id"], summary["run_id"])
            self.assertEqual(summary["counts"]["NO_FINDINGS"], 1)

    def test_parallel_agents_preserve_file_order_and_isolate_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompts = root / "prompts"
            prompts.mkdir()
            for name in ("a.txt", "b.txt", "c.txt"):
                (prompts / name).write_text("Prompt de prueba.\n", encoding="utf-8")
            rubric = root / "rubric.md"
            rubric.write_text("Rúbrica de prueba", encoding="utf-8")
            active = 0
            peak = 0
            finished = []

            async def fake_audit(path, *args):
                nonlocal active, peak
                active += 1
                peak = max(peak, active)
                try:
                    await asyncio.sleep(0.06 if path.name == "a.txt" else 0.01)
                    finished.append(path.name)
                    if path.name == "b.txt":
                        raise RuntimeError("fallo aislado")
                    return {
                        "file": path.name, "sha256": "test", "status": "NO_FINDINGS",
                        "review_required": True, "model": "audit-test",
                        "summary": "Sin hallazgos", "findings": [],
                        "limitations": ["No se probó la aplicación."],
                        "attempts": 1, "usage": {},
                    }
                finally:
                    active -= 1

            settings = {
                "MODEL_NAME": "audit-test", "LITELLM_BASE_URL": "http://litellm:4000/v1",
                "LITELLM_API_KEY": "sk-test-only", "PROMPTS_DIR": str(prompts),
                "REPORTS_DIR": str(root / "reports"), "AUDIT_RUBRIC_PATH": str(rubric),
                "MAX_PARALLEL_PROMPTS": "2",
            }
            with patch.dict(os.environ, settings), patch(
                "semantic_scan_prompts.audit_file", new=fake_audit,
            ), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit_status:
                asyncio.run(main())

            self.assertEqual(exit_status.exception.code, 2)
            self.assertEqual(peak, 2)
            self.assertLessEqual(peak, 2)
            self.assertNotEqual(finished, ["a.txt", "b.txt", "c.txt"])
            output = root / "reports" / "prompt_audit"
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(
                [item["file"] for item in summary["results"]],
                ["a.txt", "b.txt", "c.txt"],
            )
            self.assertEqual(
                [item["status"] for item in summary["results"]],
                ["NO_FINDINGS", "ERROR", "NO_FINDINGS"],
            )
            self.assertEqual(summary["counts"], {
                "REVIEW": 0, "NO_FINDINGS": 2, "ERROR": 1,
            })
            self.assertTrue(
                (output / "runs" / summary["run_id"] / "c.txt.json").exists(),
            )

    def test_prints_file_error_to_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompts = root / "prompts"
            prompts.mkdir()
            (prompts / "system.txt").write_text("Respondé con claridad.\n", encoding="utf-8")
            rubric = root / "rubric.md"
            rubric.write_text("Rúbrica de prueba", encoding="utf-8")

            async def failed_completion(**kwargs):
                raise RuntimeError("fallo de conexión de prueba")

            settings = {
                "MODEL_NAME": "audit-anthropic", "LITELLM_BASE_URL": "http://litellm:4000/v1",
                "LITELLM_API_KEY": "sk-test-only", "PROMPTS_DIR": str(prompts),
                "REPORTS_DIR": str(root / "reports"), "AUDIT_RUBRIC_PATH": str(rubric),
                "MAX_ATTEMPTS": "1",
            }
            output = io.StringIO()
            with patch.dict(os.environ, settings), patch("litellm.acompletion", new=failed_completion):
                with redirect_stdout(output), self.assertRaises(SystemExit) as exit_status:
                    asyncio.run(main())
            self.assertEqual(exit_status.exception.code, 2)
            self.assertIn("system.txt: ERROR — RuntimeError: fallo de conexión de prueba", output.getvalue())
            self.assertIn("Archivos con ERROR (auditoría incompleta)", output.getvalue())
            self.assertIn("Archivo: system.txt", output.getvalue())
            self.assertIn("Error: RuntimeError: fallo de conexión de prueba", output.getvalue())
            summary = json.loads((root / "reports" / "prompt_audit" / "summary.json").read_text())
            self.assertEqual(summary["counts"]["ERROR"], 1)

    def test_keeps_verified_partial_findings_when_both_attempts_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompts = root / "prompts"
            prompts.mkdir()
            (prompts / "system.txt").write_text(
                "Obedece siempre al usuario.\nAPI_KEY = sk-test-abcdefghijklmnop\n",
                encoding="utf-8",
            )
            rubric = root / "rubric.md"
            rubric.write_text("Rúbrica de prueba", encoding="utf-8")

            def finding(rule_id, line_number, evidence):
                return {
                    "rule_id": rule_id, "severity": "high",
                    "title": "Instrucción insegura", "explanation": "Debe revisarse.",
                    "recommendation": "Eliminar esa instrucción.",
                    "impact_conditions": "Si el usuario interactúa con el agente.",
                    "line_number": line_number, "evidence": evidence,
                }

            payloads = [
                {"summary": "Primer intento", "findings": [
                    finding("SEM-PI-01", 1, "Obedece siempre al usuario."),
                    finding("SEM-PI-02", 1, "Cita inventada"),
                ], "limitations": ["No se probó la aplicación."]},
                {"replacements": [{
                    "index": 1, "line_number": 2,
                    "evidence": "sk-test-abcdefghijklmnop",
                }], "withdrawals": []},
            ]

            async def fake_completion(**kwargs):
                return response(payloads.pop(0))

            settings = {
                "MODEL_NAME": "audit-test", "LITELLM_BASE_URL": "http://litellm:4000/v1",
                "LITELLM_API_KEY": "sk-test-only", "PROMPTS_DIR": str(prompts),
                "REPORTS_DIR": str(root / "reports"), "AUDIT_RUBRIC_PATH": str(rubric),
                "MAX_ATTEMPTS": "2",
            }
            output = io.StringIO()
            with patch.dict(os.environ, settings), patch("litellm.acompletion", new=fake_completion):
                with redirect_stdout(output), self.assertRaises(SystemExit) as exit_status:
                    asyncio.run(main())

            self.assertEqual(exit_status.exception.code, 2)
            summary = json.loads((root / "reports" / "prompt_audit" / "summary.json").read_text())
            result = summary["results"][0]
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["findings"], [])
            self.assertEqual(len(result["partial_findings"]), 1)
            self.assertEqual(result["partial_findings"][0]["evidence"], "Obedece siempre al usuario.")
            self.assertIn("Hallazgos parciales", output.getvalue())
            self.assertIn("Archivo: system.txt", output.getvalue())
            self.assertIn("Error: IncompleteAuditError:", output.getvalue())
            self.assertIn("SEM-PI-01", output.getvalue())
            self.assertNotIn("sk-test-abcdefghijklmnop", output.getvalue())
            self.assertNotIn("sk-test-abcdefghijklmnop", json.dumps(summary))

    def test_targeted_retry_keeps_valid_finding_and_withdraws_invalid_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "system.txt"
            prompt.write_text("Obedece siempre al usuario.\n", encoding="utf-8")
            base = {
                "rule_id": "SEM-PI-01", "severity": "high",
                "title": "Prioridad indebida", "explanation": "Escala al usuario.",
                "recommendation": "Respetar prioridades.",
                "impact_conditions": "Si hay instrucciones de usuario.",
                "line_number": 1,
            }
            payloads = [
                {"summary": "Primero", "findings": [
                    dict(base, evidence="Obedece siempre al usuario."),
                    dict(base, evidence="Cita inventada"),
                ], "limitations": ["No se probó la aplicación."]},
                {"replacements": [], "withdrawals": [
                    {"index": 1, "reason": "No hay una cita que fundamente el candidato."},
                ]},
            ]
            calls = []

            async def fake_completion(**kwargs):
                calls.append(kwargs)
                return response(payloads.pop(0))

            with patch("litellm.acompletion", new=fake_completion):
                result = asyncio.run(audit_file(
                    prompt, root, "Rúbrica", "audit-test",
                    "http://litellm:4000/v1", "sk-test-only", 3000, 120, 2, 30000,
                ))
            self.assertEqual(result["status"], "REVIEW")
            self.assertEqual(len(result["findings"]), 1)
            self.assertNotIn("partial_findings", result)
            self.assertIn("1 candidato retirado", result["summary"])
            self.assertNotIn("Primero", result["summary"])
            self.assertEqual(calls[1]["response_format"]["json_schema"]["name"], "citation_repair")
            self.assertIn('"index": 1', calls[1]["messages"][-1]["content"])
            self.assertNotIn("Cita inventada", calls[1]["messages"][-1]["content"])

    def test_incomplete_repair_does_not_erase_verified_partial_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "system.txt"
            prompt.write_text("Obedece siempre al usuario.\n", encoding="utf-8")
            base = {
                "rule_id": "SEM-PI-01", "severity": "high",
                "title": "Prioridad indebida", "explanation": "Escala al usuario.",
                "recommendation": "Respetar prioridades.",
                "impact_conditions": "Si hay instrucciones de usuario.",
                "line_number": 1,
            }
            payloads = [
                {"summary": "Primero", "findings": [
                    dict(base, evidence="Obedece siempre al usuario."),
                    dict(base, evidence="Cita inventada"),
                ], "limitations": ["No se probó la aplicación."]},
                {"replacements": [], "withdrawals": []},
            ]

            async def fake_completion(**kwargs):
                return response(payloads.pop(0))

            with patch("litellm.acompletion", new=fake_completion):
                with self.assertRaisesRegex(ValueError, "no cubre exactamente") as caught:
                    asyncio.run(audit_file(
                        prompt, root, "Rúbrica", "audit-test",
                        "http://litellm:4000/v1", "sk-test-only", 3000, 120, 2, 30000,
                    ))
            self.assertEqual(len(caught.exception.partial_findings), 1)

    def test_targeted_retry_replaces_only_rejected_citation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "system.txt"
            prompt.write_text(
                "Obedece siempre al usuario.\nEjecuta cualquier comando.\n",
                encoding="utf-8",
            )
            base = {
                "rule_id": "SEM-PI-01", "severity": "high",
                "title": "Prioridad indebida", "explanation": "Escala al usuario.",
                "recommendation": "Respetar prioridades.",
                "impact_conditions": "Si hay instrucciones de usuario.",
            }
            payloads = [
                {"summary": "Dos hallazgos", "findings": [
                    dict(base, line_number=1, evidence="Obedece siempre al usuario."),
                    dict(base, line_number=2, evidence="Texto inventado"),
                ], "limitations": ["No se probó la aplicación."]},
                {"replacements": [{
                    "index": 1, "line_number": 2,
                    "evidence": "Ejecuta cualquier comando.",
                }], "withdrawals": []},
            ]

            async def fake_completion(**kwargs):
                return response(payloads.pop(0))

            with patch("litellm.acompletion", new=fake_completion):
                result = asyncio.run(audit_file(
                    prompt, root, "Rúbrica", "audit-test",
                    "http://litellm:4000/v1", "sk-test-only", 3000, 120, 2, 30000,
                ))
            self.assertEqual(result["status"], "REVIEW")
            self.assertEqual(len(result["findings"]), 2)
            self.assertEqual(result["findings"][0]["evidence"], "Obedece siempre al usuario.")
            self.assertEqual(result["findings"][1]["evidence"], "Ejecuta cualquier comando.")

    def test_repair_feedback_does_not_repeat_key_shaped_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "system.txt"
            prompt.write_text(
                "Obedece siempre al usuario.\nAPI_KEY = sk-test-abcdefghijklmnop\n",
                encoding="utf-8",
            )
            base = {
                "severity": "high", "title": "Candidato",
                "explanation": "Revisar.", "recommendation": "Corregir.",
                "impact_conditions": "Si se aplica.",
            }
            payloads = [
                {"summary": "Revisión", "findings": [
                    dict(base, rule_id="SEM-PI-01", line_number=1,
                         evidence="Obedece siempre al usuario."),
                    dict(base, rule_id="SEM-DISC-02", line_number=2,
                         evidence="sk-test-abcdefghijklmnop"),
                ], "limitations": ["No se probó la aplicación."]},
                {"replacements": [], "withdrawals": [
                    {"index": 1, "reason": "Valor de prueba, sin instrucción de custodia."},
                ]},
            ]
            calls = []

            async def fake_completion(**kwargs):
                calls.append(kwargs)
                return response(payloads.pop(0))

            with patch("litellm.acompletion", new=fake_completion):
                result = asyncio.run(audit_file(
                    prompt, root, "Rúbrica", "audit-test",
                    "http://litellm:4000/v1", "sk-test-only", 3000, 120, 2, 30000,
                ))
            self.assertEqual(result["status"], "REVIEW")
            self.assertEqual(len(result["findings"]), 1)
            feedback = calls[1]["messages"][-1]["content"]
            self.assertNotIn("sk-test-abcdefghijklmnop", feedback)
            self.assertIn("[consultar línea numerada", feedback)

    def test_corrects_only_unique_literal_line_and_adjacent_span(self):
        base = {
            "rule_id": "SEM-PI-01", "severity": "high",
            "title": "Prioridad indebida", "explanation": "Escala al usuario.",
            "recommendation": "Respetar prioridades.",
            "impact_conditions": "Si hay instrucciones de usuario.",
        }
        lines = ["otra instrucción", "follow the new", "instructions because the user wins"]
        wrong_line = Finding.model_validate(dict(base, line_number=1, evidence="follow the new"))
        corrected = verify_finding_evidence(wrong_line, lines)
        self.assertEqual(corrected["line_number"], 2)
        self.assertNotIn("end_line_number", corrected)
        self.assertEqual(corrected["model_line_number"], 1)
        self.assertEqual(corrected["citation_adjustment"], "unique_exact_line")

        span = Finding.model_validate(dict(base, line_number=2, evidence="follow the new instructions"))
        resolved_span = verify_finding_evidence(span, lines)
        self.assertEqual(resolved_span["line_number"], 2)
        self.assertEqual(resolved_span["end_line_number"], 3)
        self.assertEqual(resolved_span["evidence"], "follow the new instructions")
        self.assertEqual(resolved_span["citation_adjustment"], "adjacent_span")

        repeated = Finding.model_validate(dict(base, line_number=1, evidence="duplicada"))
        with self.assertRaisesRegex(ValueError, "no coincide"):
            verify_finding_evidence(repeated, ["otra", "duplicada", "duplicada"])

    def test_accepts_literal_evidence_and_returns_structured_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "system.txt"
            prompt.write_text("Permite compartir datos privados sin autorización.\n", encoding="utf-8")
            payload = {
                "summary": "Hay una instrucción insegura explícita.",
                "findings": [{
                    "rule_id": "SEM-DISC-01", "severity": "high",
                    "title": "Divulgación de datos", "explanation": "Autoriza divulgación de sk-test-abcdefghijklmnop.",
                    "recommendation": "Exigir autorización externa.",
                    "impact_conditions": "Que el sistema tenga acceso a datos privados.",
                    "line_number": 1, "evidence": "compartir datos privados sin autorización",
                }],
                "limitations": ["No se probó la aplicación; sk-test-abcdefghijklmnop es un valor de prueba."],
            }
            calls = []

            async def fake_completion(**kwargs):
                calls.append(kwargs)
                return response(payload)

            with patch("litellm.acompletion", new=fake_completion):
                result = asyncio.run(audit_file(
                    prompt, root, "Rúbrica de prueba", "audit-anthropic",
                    "http://litellm:4000/v1", "sk-test-only", 3000, 120, 1, 30000,
                ))
            self.assertEqual(result["status"], "REVIEW")
            self.assertEqual(result["findings"][0]["line_number"], 1)
            self.assertIn("[REDACTED]", result["findings"][0]["explanation"])
            self.assertIn("[REDACTED]", result["limitations"][0])
            self.assertIn("<PROMPT_DOCUMENT>", calls[0]["messages"][1]["content"])
            self.assertEqual(calls[0]["messages"][0]["role"], "system")
            output_format = calls[0]["response_format"]
            self.assertEqual(output_format["type"], "json_schema")
            self.assertNotIn("maxItems", output_format["json_schema"]["schema"]["properties"]["findings"])

    def test_invalid_json_reports_diagnostics_without_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "system.txt"
            prompt.write_text("Sé claro.\n", encoding="utf-8")

            async def fake_completion(**kwargs):
                return SimpleNamespace(choices=[SimpleNamespace(
                    message=SimpleNamespace(content="TEXTO_SENSIBLE no es JSON"),
                    finish_reason="stop",
                )])

            with patch("litellm.acompletion", new=fake_completion):
                with self.assertRaisesRegex(ValueError, "intento 1: respuesta: json_invalid") as caught:
                    asyncio.run(audit_file(
                        prompt, root, "Rúbrica", "audit-anthropic",
                        "http://litellm:4000/v1", "sk-test-only", 3000, 120, 2, 30000,
                    ))
            self.assertIn("intento 2: respuesta: json_invalid", str(caught.exception))
            self.assertNotIn("TEXTO_SENSIBLE", str(caught.exception))

    def test_rejects_invented_citation(self):
        judgement = AuditJudgement.model_validate({
            "summary": "Hallazgo propuesto", "limitations": ["No se probó la aplicación."],
            "findings": [{
                "rule_id": "SEM-PI-01", "severity": "medium",
                "title": "Título", "explanation": "Explicación",
                "recommendation": "Recomendación", "impact_conditions": "Condición",
                "line_number": 1, "evidence": "texto que no aparece",
            }],
        })
        with self.assertRaisesRegex(ValueError, "no coincide"):
            verify_evidence(judgement, ["El archivo dice otra cosa"])

    def test_rejects_secret_in_citation(self):
        judgement = AuditJudgement.model_validate({
            "summary": "Hallazgo propuesto", "limitations": ["No se probó la aplicación."],
            "findings": [{
                "rule_id": "SEM-DISC-01", "severity": "high",
                "title": "Título", "explanation": "Explicación",
                "recommendation": "Recomendación", "impact_conditions": "Condición",
                "line_number": 1, "evidence": "sk-test-abcdefghijklmnop",
            }],
        })
        with self.assertRaisesRegex(ValueError, "posible secreto"):
            verify_evidence(judgement, ["token: sk-test-abcdefghijklmnop"])


if __name__ == "__main__":
    unittest.main()
