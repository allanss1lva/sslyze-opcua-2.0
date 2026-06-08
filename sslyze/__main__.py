import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TextIO

from sslyze.cli.console_output import ObserverToGenerateConsoleOutput
from sslyze.__version__ import __version__
from sslyze.cli.command_line_parser import CommandLineParsingError, CommandLineParser

from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerScanResultAsJson,
    ServerConnectivityStatusEnum,
)
from sslyze.json.json_output import InvalidServerStringAsJson
from sslyze.mozilla_tls_profile.tls_config_checker import (
    check_server_against_tls_configuration,
    ServerNotCompliantWithTlsConfiguration,
    ServerScanResultIncomplete,
    TlsConfigurationEnum,
)

# Caminhos padrão da integração OPC UA: política de validação e relatório de saída.
# Se o arquivo de política não existir, a validação OPC UA é simplesmente ignorada.
_OPCUA_POLICY_PATH = Path("policies/default_opcua_policy.json")
_OPCUA_REPORT_PATH = Path("opcua_validation_report.json")


def main() -> None:
    # Parse the supplied command line
    date_scans_started = datetime.now(timezone.utc)
    sslyze_parser = CommandLineParser(__version__)
    try:
        parsed_command_line = sslyze_parser.parse_command_line()
    except CommandLineParsingError as e:
        print(e.get_error_msg())
        return

    # Setup the observer to print to the console, if needed
    scanner_observers = []
    if not parsed_command_line.should_disable_console_output:
        observer_for_console_output = ObserverToGenerateConsoleOutput(
            file_to=sys.stdout, json_path_out=parsed_command_line.json_path_out
        )
        observer_for_console_output.command_line_parsed(parsed_command_line=parsed_command_line)

        scanner_observers.append(observer_for_console_output)

    # Ativa validação OPC UA automaticamente se o arquivo de política existir.
    # O import é feito aqui dentro (lazy) para não impactar execuções sem OPC UA.
    # O observer é registrado no scanner e será notificado ao fim de cada scan de servidor.
    opcua_observer = None
    if _OPCUA_POLICY_PATH.exists():
        from sslyze.plugins.certificate_info._opcua_validator import load_policy
        from sslyze.scanner.opcua_validation_observer import OpcuaValidationObserver

        opcua_observer = OpcuaValidationObserver(load_policy(_OPCUA_POLICY_PATH), _OPCUA_REPORT_PATH)
        scanner_observers.append(opcua_observer)

    # Setup the scanner
    sslyze_scanner = Scanner(
        per_server_concurrent_connections_limit=parsed_command_line.per_server_concurrent_connections_limit,
        concurrent_server_scans_limit=parsed_command_line.concurrent_server_scans_limit,
        observers=scanner_observers,
    )

    # Queue the scans
    all_server_scan_requests = []
    for server_location, network_config in parsed_command_line.servers_to_scans:
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands=parsed_command_line.scan_commands,
            scan_commands_extra_arguments=parsed_command_line.scan_commands_extra_arguments,
        )
        all_server_scan_requests.append(scan_request)

    # If there are servers that we were able to resolve, scan them
    all_server_scan_results = []
    if all_server_scan_requests:
        sslyze_scanner.queue_scans(all_server_scan_requests)
        for result in sslyze_scanner.get_results():
            # Results are actually displayed by the observer; here we just store them
            all_server_scan_results.append(result)

    # Write results to a JSON file if needed
    json_file_out: Optional[TextIO] = None
    if parsed_command_line.should_print_json_to_console:
        json_file_out = sys.stdout
    elif parsed_command_line.json_path_out:
        json_file_out = parsed_command_line.json_path_out.open("wt", encoding="utf-8")

    if json_file_out:
        json_output = SslyzeOutputAsJson(
            server_scan_results=[ServerScanResultAsJson.model_validate(result) for result in all_server_scan_results],
            invalid_server_strings=[
                InvalidServerStringAsJson.model_validate(bad_server)
                for bad_server in parsed_command_line.invalid_servers
            ],
            date_scans_started=date_scans_started,
            date_scans_completed=datetime.now(timezone.utc),
        )
        json_output_as_str = json_output.model_dump_json(indent=2)
        json_file_out.write(json_output_as_str)

    # If we printed the JSON results to the console, don't run the TLS compliance check so we return valid JSON
    if parsed_command_line.should_print_json_to_console:
        sys.exit(0)

    if {res.connectivity_status for res in all_server_scan_results} in [set(), {ServerConnectivityStatusEnum.ERROR}]:
        # There are no results to present: all supplied server strings were invalid?
        sys.exit(0)

    # Check the results against the TLS config if needed
    are_all_servers_compliant = True
    # TODO(AD): Expose format_title method
    title = ObserverToGenerateConsoleOutput._format_title("Compliance against TLS configuration")
    print()
    print(title)
    if not parsed_command_line.tls_config_to_check_against_as_enum:
        print(
            "    Disabled; use --mozilla_config={old, intermediate, modern} or --custom_tls_config=path/to/profile.json.\n"
        )
    else:
        assert parsed_command_line.tls_config_to_check_against, "Should always be set"

        if parsed_command_line.tls_config_to_check_against_as_enum == TlsConfigurationEnum.CUSTOM:
            print("    Checking results against custom TLS configuration.\n")
        else:
            config_name = parsed_command_line.tls_config_to_check_against_as_enum.value
            print(
                f'    Checking results against Mozilla\'s "{config_name}"'
                f" configuration. See https://ssl-config.mozilla.org/ for more details.\n"
            )

        for server_scan_result in all_server_scan_results:
            try:
                check_server_against_tls_configuration(
                    server_scan_result=server_scan_result,
                    tls_config_to_check_against=parsed_command_line.tls_config_to_check_against,
                )
                print(f"    {server_scan_result.server_location.display_string}: OK - Compliant.\n")

            except ServerNotCompliantWithTlsConfiguration as e:
                are_all_servers_compliant = False
                print(f"    {server_scan_result.server_location.display_string}: FAILED - Not compliant.")
                for criteria, error_description in e.issues.items():
                    print(f"        * {criteria}: {error_description}")
                print()

            except ServerScanResultIncomplete:
                are_all_servers_compliant = False
                print(
                    f"    {server_scan_result.server_location.display_string}: ERROR - Scan did not run successfully;"
                    f" review the scan logs above."
                )

    if not are_all_servers_compliant:
        # Return a non-zero error code to signal failure (for example to fail a CI/CD pipeline)
        sys.exit(1)

    # Exibe o resumo OPC UA no terminal após o bloco de conformidade TLS.
    # O relatório JSON já foi gravado pelo observer durante o scan; aqui apenas o lemos e imprimimos.
    if opcua_observer and _OPCUA_REPORT_PATH.exists():
        _print_opcua_validation_section(_OPCUA_REPORT_PATH)


def _print_opcua_validation_section(report_path: Path) -> None:
    """Lê o relatório OPC UA gerado pelo observer e imprime o resumo no terminal.

    O status de cada servidor é derivado do relatório JSON já gravado em disco:
    REPROVADO se houver erros críticos, APROVADO COM AVISOS se houver apenas warnings,
    APROVADO se todas as regras passaram sem ressalvas.
    """
    report = json.loads(report_path.read_text(encoding="utf-8"))
    title = ObserverToGenerateConsoleOutput._format_title("Validação OPC UA v2.0")
    print(title)
    for srv in report["servers"]:
        # Determina o status consolidado do servidor com base nos contadores do relatório
        if not srv["all_passed"]:
            status = "REPROVADO"
        elif srv["warning_count"] > 0:
            status = "APROVADO COM AVISOS"
        else:
            status = "APROVADO"
        print(f"   Servidor  : {srv['server']}")
        print(f"   Resultado : {status}  |  Erros: {srv['error_count']}  |  Avisos: {srv['warning_count']}\n")
        # Imprime o resultado de cada regra com flag OK/FALHA, severidade e mensagem
        for r in srv["results"]:
            flag = "OK   " if r["passed"] else "FALHA"
            print(f"   [{flag}] [{r['severity']:<7}] {r['rule_id']:<22}  {r['message']}")
    print(f"\n   Relatório JSON salvo em: {report_path}\n")


if __name__ == "__main__":
    main()
