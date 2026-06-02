"""ScannerObserver que executa validações OPC UA e salva o relatório em JSON.

Uso:
    policy = load_policy(Path("policies/default_opcua_policy.json"))
    observer = OpcuaValidationObserver(policy, Path("opcua_validation_report.json"))
    scanner = Scanner(observers=[observer])
    scanner.queue_scans([request])
    for _ in scanner.get_results():
        pass
    # → relatório salvo em opcua_validation_report.json
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sslyze import ServerScanRequest, ServerScanResult, ServerTlsProbingResult
from sslyze.errors import ConnectionToServerFailed
from sslyze.plugins.certificate_info._opcua_validator import (
    OpcuaCertificateValidator,
    OpcuaPolicyConfig,
    ValidationResult,
    ValidationSeverity,
)
from sslyze.scanner.models import ServerScanStatusEnum
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum
from sslyze.scanner.scanner_observer import ScannerObserver


@dataclass
class _ServerReport:
    server: str
    all_passed: bool
    error_count: int
    warning_count: int
    results: List[ValidationResult]


class OpcuaValidationObserver(ScannerObserver):
    """Coleta resultados de scan, executa as regras da política e salva JSON."""

    def __init__(self, policy: OpcuaPolicyConfig, output_path: Path) -> None:
        self._validator = OpcuaCertificateValidator(policy)
        self._policy = policy
        self._output_path = output_path
        self._reports: List[_ServerReport] = []

    # ── Callbacks obrigatórios do ScannerObserver ────────────────────────────

    def server_connectivity_test_error(
        self,
        server_scan_request: ServerScanRequest,
        connectivity_error: ConnectionToServerFailed,
    ) -> None:
        pass

    def server_connectivity_test_completed(
        self,
        server_scan_request: ServerScanRequest,
        connectivity_result: ServerTlsProbingResult,
    ) -> None:
        pass

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
            return
        if not server_scan_result.scan_result:
            return

        cert_attempt = server_scan_result.scan_result.certificate_info
        if cert_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return
        if not cert_attempt.result or not cert_attempt.result.certificate_deployments:
            return

        leaf_cert = cert_attempt.result.certificate_deployments[0].received_certificate_chain[0]
        results = self._validator.validate(leaf_cert)

        loc = server_scan_result.server_location
        error_count = sum(1 for r in results if not r.passed and r.severity == ValidationSeverity.ERROR)
        warning_count = sum(1 for r in results if not r.passed and r.severity == ValidationSeverity.WARNING)
        self._reports.append(
            _ServerReport(
                server=f"{loc.hostname}:{loc.port}",
                all_passed=error_count == 0,
                error_count=error_count,
                warning_count=warning_count,
                results=results,
            )
        )

    def all_server_scans_completed(self) -> None:
        self._save_report()

    # ── Serialização ─────────────────────────────────────────────────────────

    def _save_report(self) -> None:
        output = {
            "date": datetime.now(timezone.utc).isoformat(),
            "policy": self._policy.model_dump(),
            "servers": [
                {
                    "server": r.server,
                    "all_passed": r.all_passed,
                    "error_count": r.error_count,
                    "warning_count": r.warning_count,
                    "results": [asdict(result) for result in r.results],
                }
                for r in self._reports
            ],
        }
        self._output_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
