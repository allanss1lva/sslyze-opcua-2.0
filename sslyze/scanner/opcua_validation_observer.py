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


# Agrupa os resultados de validação de um único servidor para serialização no relatório final.
@dataclass
class _ServerReport:
    server: str                      # Endereço no formato "hostname:porta"
    all_passed: bool                 # True somente se nenhum erro crítico foi encontrado
    error_count: int                 # Número de regras com severidade ERROR que falharam
    warning_count: int               # Número de regras com severidade WARNING que falharam
    results: List[ValidationResult]  # Resultado detalhado de cada regra aplicada


class OpcuaValidationObserver(ScannerObserver):
    """Coleta resultados de scan, executa as regras da política e salva JSON.

    Implementa o padrão Observer do sslyze: o Scanner notifica esta classe
    via callbacks a cada etapa do processo de varredura. Ao final, o relatório
    consolidado é gravado no arquivo de saída configurado.
    """

    def __init__(self, policy: OpcuaPolicyConfig, output_path: Path) -> None:
        # Instancia o validador com as regras da política fornecida
        self._validator = OpcuaCertificateValidator(policy)
        self._policy = policy
        self._output_path = output_path
        self._reports: List[_ServerReport] = []  # Acumula relatórios de cada servidor escaneado

    # ── Callbacks obrigatórios do ScannerObserver ────────────────────────────

    def server_connectivity_test_error(
        self,
        server_scan_request: ServerScanRequest,
        connectivity_error: ConnectionToServerFailed,
    ) -> None:
        # Servidores inacessíveis são ignorados — sem certificado para validar
        pass

    def server_connectivity_test_completed(
        self,
        server_scan_request: ServerScanRequest,
        connectivity_result: ServerTlsProbingResult,
    ) -> None:
        # Conexão bem-sucedida; a validação ocorre após o scan completo em server_scan_completed
        pass

    def server_scan_completed(self, server_scan_result: ServerScanResult) -> None:
        """Executado pelo Scanner ao terminar a varredura de um servidor.

        Extrai o certificado folha (leaf certificate) da cadeia recebida,
        executa todas as regras de validação OPC UA e armazena o relatório do servidor.
        """
        # Ignora servidores cujo scan não foi concluído com sucesso
        if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
            return
        if not server_scan_result.scan_result:
            return

        # Verifica se o plugin de certificate_info executou sem erros
        cert_attempt = server_scan_result.scan_result.certificate_info
        if cert_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return
        if not cert_attempt.result or not cert_attempt.result.certificate_deployments:
            return

        # O certificado folha é o primeiro da cadeia recebida — é o do próprio servidor
        leaf_cert = cert_attempt.result.certificate_deployments[0].received_certificate_chain[0]
        results = self._validator.validate(leaf_cert)

        loc = server_scan_result.server_location
        # Conta separadamente erros críticos e avisos para o sumário do relatório
        error_count = sum(1 for r in results if not r.passed and r.severity == ValidationSeverity.ERROR)
        warning_count = sum(1 for r in results if not r.passed and r.severity == ValidationSeverity.WARNING)
        self._reports.append(
            _ServerReport(
                server=f"{loc.hostname}:{loc.port}",
                all_passed=error_count == 0,  # all_passed=True apenas se não houver ERRORs
                error_count=error_count,
                warning_count=warning_count,
                results=results,
            )
        )

    def all_server_scans_completed(self) -> None:
        """Executado pelo Scanner após todos os servidores serem processados.

        Dispara a gravação do relatório final em disco.
        """
        self._save_report()

    # ── Serialização ─────────────────────────────────────────────────────────

    def _save_report(self) -> None:
        """Serializa todos os relatórios coletados em um único arquivo JSON.

        O arquivo inclui: data/hora da execução, política aplicada e o resultado
        detalhado de cada servidor, com contagem de erros e o resultado de cada regra.
        """
        output = {
            "date": datetime.now(timezone.utc).isoformat(),
            "policy": self._policy.model_dump(),   # Política usada, para auditoria e rastreabilidade
            "servers": [
                {
                    "server": r.server,
                    "all_passed": r.all_passed,
                    "error_count": r.error_count,
                    "warning_count": r.warning_count,
                    "results": [asdict(result) for result in r.results],  # Converte dataclasses para dict
                }
                for r in self._reports
            ],
        }
        self._output_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False),  # ensure_ascii=False preserva acentos nas mensagens
            encoding="utf-8",
        )
