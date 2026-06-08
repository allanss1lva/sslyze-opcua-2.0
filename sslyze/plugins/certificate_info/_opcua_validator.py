"""Validação customizável de certificados X.509 para servidores OPC UA.

Uso:
    policy = load_policy(Path("policies/default_opcua_policy.json"))
    validator = OpcuaCertificateValidator(policy)
    results = validator.validate(cert)  # cert: x509.Certificate (cryptography)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List, Protocol, runtime_checkable

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from pydantic import BaseModel


# Níveis de severidade usados para classificar o resultado de cada regra de validação.
# INFO: apenas informativo; WARNING: recomendação não obrigatória; ERROR: falha crítica de segurança.
class ValidationSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


# Estrutura imutável que representa o resultado de uma única regra aplicada ao certificado.
# 'passed=False' com severity ERROR indica que o certificado não atende aos requisitos mínimos de segurança OPC UA.
@dataclass(frozen=True)
class ValidationResult:
    rule_id: str          # Identificador único da regra (ex: "KEY_SIZE")
    name: str             # Nome legível da regra
    severity: ValidationSeverity
    passed: bool          # True se o certificado atendeu à regra
    message: str          # Mensagem descritiva do resultado


# Protocolo (interface) que todas as regras de validação devem implementar.
# Usar Protocol com @runtime_checkable permite verificar via isinstance() sem herança explícita.
@runtime_checkable
class OpcuaValidationRule(Protocol):
    rule_id: str
    name: str
    severity: ValidationSeverity

    def validate(self, cert: x509.Certificate) -> ValidationResult: ...


# ── Regras concretas ────────────────────────────────────────────────────────


class SelfSignedRule:
    """Verifica se o certificado é autoassinado e se a política permite isso.

    Certificados autoassinados são comuns em ambientes industriais OPC UA isolados,
    por isso a política pode configurá-los como permitidos (allow=True).
    """

    rule_id = "SELF_SIGNED"
    name = "Certificado autoassinado"
    severity = ValidationSeverity.WARNING

    def __init__(self, allow: bool) -> None:
        # Se allow=False, certificados autoassinados causarão falha na validação
        self._allow = allow

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        # Um certificado é autoassinado quando emissor e sujeito são idênticos
        is_self_signed = cert.issuer == cert.subject
        if is_self_signed and not self._allow:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message="Certificado autoassinado não é permitido pela política",
            )
        return ValidationResult(
            rule_id=self.rule_id, name=self.name, severity=self.severity, passed=True, message="OK"
        )


class NotExpiredRule:
    """Verifica se o certificado ainda está dentro do seu prazo de validade."""

    rule_id = "NOT_EXPIRED"
    name = "Certificado não expirado"
    severity = ValidationSeverity.ERROR

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        now = datetime.now(timezone.utc)
        if now > cert.not_valid_after_utc:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"Certificado expirou em {cert.not_valid_after_utc.date()}",
            )
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"Válido até {cert.not_valid_after_utc.date()}",
        )


class NotYetValidRule:
    """Verifica se o certificado já é válido (data de início não está no futuro)."""

    rule_id = "NOT_YET_VALID"
    name = "Certificado com validade futura"
    severity = ValidationSeverity.ERROR

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"Certificado só é válido a partir de {cert.not_valid_before_utc.date()}",
            )
        return ValidationResult(
            rule_id=self.rule_id, name=self.name, severity=self.severity, passed=True, message="OK"
        )


class MaxValidityDaysRule:
    """Garante que o período de validade do certificado não ultrapassa o limite definido na política.

    Certificados com vida útil muito longa aumentam o risco de comprometimento de chave sem renovação.
    O padrão OPC UA recomenda no máximo 5 anos (1825 dias) para certificados de aplicação.
    """

    rule_id = "MAX_VALIDITY"
    name = "Validade máxima do certificado"
    severity = ValidationSeverity.WARNING

    def __init__(self, max_days: int) -> None:
        self._max_days = max_days

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        # Calcula a vida útil total do certificado em dias
        lifespan = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        if lifespan > self._max_days:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"Validade de {lifespan} dias excede o limite de {self._max_days} dias",
            )
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"Validade de {lifespan} dias dentro do limite",
        )


class KeySizeRule:
    """Verifica se o tamanho da chave pública atende ao mínimo de segurança exigido.

    Para RSA, chaves menores que 2048 bits são consideradas inseguras.
    Chaves EC são sempre consideradas aceitáveis, pois oferecem segurança equivalente com tamanhos menores.
    """

    rule_id = "KEY_SIZE"
    name = "Tamanho mínimo da chave"
    severity = ValidationSeverity.ERROR

    def __init__(self, min_rsa_bits: int) -> None:
        self._min_rsa_bits = min_rsa_bits

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            size = public_key.key_size
            if size < self._min_rsa_bits:
                return ValidationResult(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    passed=False,
                    message=f"Chave RSA de {size} bits abaixo do mínimo de {self._min_rsa_bits} bits",
                )
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=True,
                message=f"Chave RSA de {size} bits",
            )
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            size = public_key.key_size
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=True,
                message=f"Chave EC de {size} bits",
            )
        # Tipo de chave desconhecido (ex: Ed25519) — aprovado sem verificação de tamanho
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"Tipo de chave não verificado: {type(public_key).__name__}",
        )


class SignatureAlgorithmRule:
    """Verifica se o algoritmo de hash usado na assinatura do certificado está na lista de permitidos.

    Algoritmos fracos como MD5 e SHA-1 são vulneráveis a colisões e não devem ser aceitos.
    A lista padrão exige SHA-256 ou superior.
    """

    rule_id = "SIG_ALGORITHM"
    name = "Algoritmo de assinatura permitido"
    severity = ValidationSeverity.ERROR

    def __init__(self, allowed: List[str]) -> None:
        # Normaliza para minúsculas para comparação case-insensitive
        self._allowed = [a.lower() for a in allowed]

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        alg = cert.signature_hash_algorithm
        if alg is None:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message="Algoritmo de hash não identificado",
            )
        name = alg.name.lower()
        if name not in self._allowed:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"Algoritmo '{alg.name}' não está na lista permitida: {self._allowed}",
            )
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"Algoritmo '{alg.name}' permitido",
        )


class BasicConstraintsRule:
    """Verifica a extensão BasicConstraints para garantir que o certificado não seja uma CA.

    Certificados de aplicação OPC UA não devem ter CA=True, pois isso permitiria
    que fossem usados para assinar outros certificados, violando a hierarquia de confiança.
    """

    rule_id = "BASIC_CONSTRAINTS"
    name = "Extensão BasicConstraints"
    severity = ValidationSeverity.ERROR

    def __init__(self, require: bool) -> None:
        # Se require=True, a ausência da extensão também é considerada falha
        self._require = require

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            if self._require:
                return ValidationResult(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    passed=False,
                    message="Extensão BasicConstraints ausente",
                )
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=True,
                message="BasicConstraints ausente (não obrigatória pela política)",
            )
        # CA=True indica certificado de autoridade certificadora — inválido para aplicações OPC UA
        if bc.ca:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message="Certificado de aplicação OPC UA não deve ter CA=True",
            )
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message="BasicConstraints presente e CA=False",
        )


class KeyUsageRule:
    """Verifica se a extensão KeyUsage contém os bits de uso obrigatórios pela política.

    Para OPC UA, 'digitalSignature' é necessário para autenticação e 'keyEncipherment'
    para troca de chaves de sessão TLS.
    """

    rule_id = "KEY_USAGE"
    name = "Extensão KeyUsage"
    severity = ValidationSeverity.WARNING

    def __init__(self, require: bool, require_digital_signature: bool, require_key_encipherment: bool) -> None:
        self._require = require
        self._require_digital_signature = require_digital_signature
        self._require_key_encipherment = require_key_encipherment

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            if self._require:
                return ValidationResult(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    passed=False,
                    message="Extensão KeyUsage ausente",
                )
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=True,
                message="KeyUsage ausente (não obrigatória pela política)",
            )

        # Coleta os bits obrigatórios que estão ausentes no certificado
        missing = []
        if self._require_digital_signature and not ku.digital_signature:
            missing.append("digitalSignature")
        if self._require_key_encipherment and not ku.key_encipherment:
            missing.append("keyEncipherment")

        if missing:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"Bits obrigatórios ausentes no KeyUsage: {', '.join(missing)}",
            )
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message="KeyUsage presente com bits obrigatórios",
        )


class ExtendedKeyUsageRule:
    """Verifica se a extensão ExtendedKeyUsage contém os OIDs de autenticação exigidos.

    'serverAuth' garante que o certificado pode ser usado por um servidor TLS.
    'clientAuth' garante que pode ser usado por um cliente TLS.
    Em OPC UA, ambos os papéis podem coexistir no mesmo certificado de aplicação.
    """

    rule_id = "EXTENDED_KEY_USAGE"
    name = "Extensão ExtendedKeyUsage"
    severity = ValidationSeverity.WARNING

    def __init__(self, require: bool, require_server_auth: bool, require_client_auth: bool) -> None:
        self._require = require
        self._require_server_auth = require_server_auth
        self._require_client_auth = require_client_auth

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            if self._require:
                return ValidationResult(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    passed=False,
                    message="Extensão ExtendedKeyUsage ausente",
                )
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=True,
                message="ExtendedKeyUsage ausente (não obrigatória pela política)",
            )

        present = list(eku)
        # Verifica quais OIDs obrigatórios estão faltando
        missing = []
        if self._require_server_auth and ExtendedKeyUsageOID.SERVER_AUTH not in present:
            missing.append("serverAuth")
        if self._require_client_auth and ExtendedKeyUsageOID.CLIENT_AUTH not in present:
            missing.append("clientAuth")

        if missing:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"OIDs obrigatórios ausentes no ExtendedKeyUsage: {', '.join(missing)}",
            )
        oid_names = [oid.dotted_string for oid in present]
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"ExtendedKeyUsage presente: {oid_names}",
        )


class SubjectAltNameUriRule:
    """Verifica se o certificado possui um URI OPC UA no campo SubjectAlternativeName.

    A especificação OPC UA (Part 6) exige que o ApplicationUri da aplicação esteja
    presente no SAN como um URI no formato 'urn:...'. Isso vincula o certificado
    à identidade da aplicação e evita reutilização em outros contextos.
    """

    rule_id = "SAN_URI"
    name = "SubjectAltName com URI OPC UA"
    severity = ValidationSeverity.WARNING

    def __init__(self, require: bool) -> None:
        self._require = require

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            if self._require:
                return ValidationResult(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    passed=False,
                    message="Extensão SubjectAltName ausente (OPC UA requer ApplicationUri)",
                )
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=True,
                message="SubjectAltName ausente (não obrigatória pela política)",
            )
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        # URIs OPC UA seguem o padrão "urn:<domínio>:<aplicação>"
        opc_uris = [u for u in uris if u.startswith("urn:")]
        if not opc_uris:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"SubjectAltName não contém URI OPC UA (urn:...). URIs encontradas: {list(uris)}",
            )
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"URI OPC UA presente: {opc_uris[0]}",
        )


class CrlDistributionPointsRule:
    """Verifica se o certificado informa uma URL para verificação de revogação (CRL).

    Sem CRL Distribution Points, não é possível verificar automaticamente se o certificado
    foi revogado antes do seu vencimento. Em redes industriais isoladas isso pode ser aceitável,
    por isso a obrigatoriedade é configurável na política.
    """

    rule_id = "CRL_DISTRIBUTION_POINTS"
    name = "CRL Distribution Points"
    severity = ValidationSeverity.WARNING

    def __init__(self, require: bool) -> None:
        self._require = require

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        try:
            cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        except x509.ExtensionNotFound:
            if self._require:
                return ValidationResult(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    passed=False,
                    message="CRLDistributionPoints ausente — revogação não verificável",
                )
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=True,
                message="CRLDistributionPoints ausente (não obrigatória pela política)",
            )
        # Extrai as URLs dos Distribution Points para exibição no relatório
        urls = [dp.full_name[0].value for dp in cdp if dp.full_name]
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"CRL URL: {urls[0] if urls else 'presente'}",
        )


class CriticalExtensionsRule:
    """Verifica se as extensões BasicConstraints e KeyUsage estão marcadas como 'critical'.

    Extensões marcadas como critical devem ser compreendidas e respeitadas por qualquer
    software que processe o certificado. Se não forem critical, um cliente pode ignorá-las,
    o que comprometeria as restrições de uso definidas para o certificado OPC UA.
    """

    rule_id = "CRITICAL_EXTENSIONS"
    name = "Extensões BasicConstraints e KeyUsage marcadas como critical"
    severity = ValidationSeverity.WARNING

    def validate(self, cert: x509.Certificate) -> ValidationResult:
        non_critical = []
        for ext_class in [x509.BasicConstraints, x509.KeyUsage]:
            try:
                ext = cert.extensions.get_extension_for_class(ext_class)
                if not ext.critical:
                    non_critical.append(ext_class.__name__)
            except x509.ExtensionNotFound:
                pass  # Ausência é tratada pelas regras específicas de cada extensão
        if non_critical:
            return ValidationResult(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                passed=False,
                message=f"Extensões não marcadas como critical: {', '.join(non_critical)}",
            )
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message="BasicConstraints e KeyUsage marcadas como critical",
        )


# ── Política ────────────────────────────────────────────────────────────────


class OpcuaPolicyConfig(BaseModel):
    """Política de validação de certificados OPC UA. Carregada a partir de JSON.

    Cada campo corresponde a uma regra de validação. Os valores padrão refletem
    os requisitos mínimos recomendados pela especificação OPC UA Part 6.
    """

    allow_self_signed: bool = True                                          # Permite certificados autoassinados
    max_validity_days: int = 3650                                           # Validade máxima (~10 anos)
    min_rsa_key_size: int = 2048                                            # Tamanho mínimo de chave RSA em bits
    allowed_signature_algorithms: List[str] = ["sha256", "sha384", "sha512"]  # Algoritmos de hash aceitos
    require_basic_constraints: bool = True                                  # Exige extensão BasicConstraints
    require_key_usage: bool = True                                          # Exige extensão KeyUsage
    require_digital_signature: bool = True                                  # Exige bit digitalSignature no KeyUsage
    require_key_encipherment: bool = True                                   # Exige bit keyEncipherment no KeyUsage
    require_extended_key_usage: bool = False                                # Exige extensão ExtendedKeyUsage
    require_server_auth: bool = False                                       # Exige OID serverAuth no EKU
    require_client_auth: bool = False                                       # Exige OID clientAuth no EKU
    require_san_uri: bool = True                                            # Exige URI OPC UA no SubjectAltName
    require_crl_distribution_points: bool = False                           # Exige ponto de distribuição de CRL


def load_policy(path: Path) -> OpcuaPolicyConfig:
    """Lê e deserializa a política de validação a partir de um arquivo JSON."""
    return OpcuaPolicyConfig.model_validate_json(path.read_text(encoding="utf-8"))


def save_policy(config: OpcuaPolicyConfig, path: Path) -> None:
    """Serializa a política de validação para um arquivo JSON formatado."""
    path.write_text(config.model_dump_json(indent=2), encoding="utf-8")


# ── Validador ────────────────────────────────────────────────────────────────


def _build_rules(policy: OpcuaPolicyConfig) -> List[OpcuaValidationRule]:
    """Instancia todas as regras de validação configuradas com os parâmetros da política."""
    return [  # type: ignore[return-value]
        SelfSignedRule(allow=policy.allow_self_signed),
        NotExpiredRule(),
        NotYetValidRule(),
        MaxValidityDaysRule(max_days=policy.max_validity_days),
        KeySizeRule(min_rsa_bits=policy.min_rsa_key_size),
        SignatureAlgorithmRule(allowed=policy.allowed_signature_algorithms),
        BasicConstraintsRule(require=policy.require_basic_constraints),
        KeyUsageRule(
            require=policy.require_key_usage,
            require_digital_signature=policy.require_digital_signature,
            require_key_encipherment=policy.require_key_encipherment,
        ),
        ExtendedKeyUsageRule(
            require=policy.require_extended_key_usage,
            require_server_auth=policy.require_server_auth,
            require_client_auth=policy.require_client_auth,
        ),
        SubjectAltNameUriRule(require=policy.require_san_uri),
        CrlDistributionPointsRule(require=policy.require_crl_distribution_points),
        CriticalExtensionsRule(),
    ]


class OpcuaCertificateValidator:
    """Executa todas as regras da política sobre um certificado X.509.

    Recebe uma política configurada e aplica cada regra ao certificado informado,
    retornando a lista completa de resultados para análise ou geração de relatório.
    """

    def __init__(self, policy: OpcuaPolicyConfig) -> None:
        # Constrói e armazena as instâncias das regras uma única vez por política
        self._rules = _build_rules(policy)

    def validate(self, cert: x509.Certificate) -> List[ValidationResult]:
        """Aplica todas as regras ao certificado e retorna um resultado por regra."""
        return [rule.validate(cert) for rule in self._rules]
