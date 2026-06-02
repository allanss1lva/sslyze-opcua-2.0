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


class ValidationSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ValidationResult:
    rule_id: str
    name: str
    severity: ValidationSeverity
    passed: bool
    message: str


@runtime_checkable
class OpcuaValidationRule(Protocol):
    rule_id: str
    name: str
    severity: ValidationSeverity

    def validate(self, cert: x509.Certificate) -> ValidationResult: ...


# ── Regras concretas ────────────────────────────────────────────────────────


class SelfSignedRule:
    rule_id = "SELF_SIGNED"
    name = "Certificado autoassinado"
    severity = ValidationSeverity.WARNING

    def __init__(self, allow: bool) -> None:
        self._allow = allow

    def validate(self, cert: x509.Certificate) -> ValidationResult:
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
    rule_id = "MAX_VALIDITY"
    name = "Validade máxima do certificado"
    severity = ValidationSeverity.WARNING

    def __init__(self, max_days: int) -> None:
        self._max_days = max_days

    def validate(self, cert: x509.Certificate) -> ValidationResult:
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
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"Tipo de chave não verificado: {type(public_key).__name__}",
        )


class SignatureAlgorithmRule:
    rule_id = "SIG_ALGORITHM"
    name = "Algoritmo de assinatura permitido"
    severity = ValidationSeverity.ERROR

    def __init__(self, allowed: List[str]) -> None:
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
    rule_id = "BASIC_CONSTRAINTS"
    name = "Extensão BasicConstraints"
    severity = ValidationSeverity.ERROR

    def __init__(self, require: bool) -> None:
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
        urls = [dp.full_name[0].value for dp in cdp if dp.full_name]
        return ValidationResult(
            rule_id=self.rule_id,
            name=self.name,
            severity=self.severity,
            passed=True,
            message=f"CRL URL: {urls[0] if urls else 'presente'}",
        )


class CriticalExtensionsRule:
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
                pass
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
    """Política de validação de certificados OPC UA. Carregada a partir de JSON."""

    allow_self_signed: bool = True
    max_validity_days: int = 3650
    min_rsa_key_size: int = 2048
    allowed_signature_algorithms: List[str] = ["sha256", "sha384", "sha512"]
    require_basic_constraints: bool = True
    require_key_usage: bool = True
    require_digital_signature: bool = True
    require_key_encipherment: bool = True
    require_extended_key_usage: bool = False
    require_server_auth: bool = False
    require_client_auth: bool = False
    require_san_uri: bool = True
    require_crl_distribution_points: bool = False


def load_policy(path: Path) -> OpcuaPolicyConfig:
    return OpcuaPolicyConfig.model_validate_json(path.read_text(encoding="utf-8"))


def save_policy(config: OpcuaPolicyConfig, path: Path) -> None:
    path.write_text(config.model_dump_json(indent=2), encoding="utf-8")


# ── Validador ────────────────────────────────────────────────────────────────


def _build_rules(policy: OpcuaPolicyConfig) -> List[OpcuaValidationRule]:
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
    """Executa as regras da política sobre um certificado X.509."""

    def __init__(self, policy: OpcuaPolicyConfig) -> None:
        self._rules = _build_rules(policy)

    def validate(self, cert: x509.Certificate) -> List[ValidationResult]:
        return [rule.validate(cert) for rule in self._rules]
