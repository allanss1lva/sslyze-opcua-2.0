# SSLyze OPC UA — Análise de Certificados X.509 em Servidores OPC UA

> Adaptação da ferramenta [SSLyze](https://github.com/nabla-c0d3/sslyze) para extração e análise de certificados digitais X.509 em servidores que operam sob o protocolo **OPC UA**, em substituição à camada TLS convencional.

Desenvolvido no âmbito do **UFCG** (Universidade Federal de Campina Grande), Abril de 2026.

---

## Sumário

- [Visão Geral](#visão-geral)
- [Motivação](#motivação)
- [Arquitetura das Modificações](#arquitetura-das-modificações)
- [Pré-requisitos](#pré-requisitos)
- [Instalação e Configuração](#instalação-e-configuração)
- [Uso](#uso)
- [Resultados Esperados](#resultados-esperados)
- [Validação](#validação)
- [Limitações Conhecidas](#limitações-conhecidas)
- [v2.0 — Validação por Política Configurável](#v20--validação-por-política-configurável)
- [Referências](#referências)

---

## Visão Geral

Este projeto adapta o **SSLyze 6.3.1** — ferramenta de análise de servidores TLS/SSL — para inspecionar certificados X.509 em servidores **OPC UA** (Open Platform Communications Unified Architecture). A comunicação TLS é substituída por conexões TCP simples combinadas ao serviço `GetEndpoints` do protocolo OPC UA, via biblioteca `asyncua`.

```
SSLyze Original          →    SSLyze OPC UA (este repositório)
──────────────────────────────────────────────────────────────
Conexão TLS (nassl)      →    Conexão TCP simples (socket)
Certificado via TLS      →    Certificado via GetEndpoints (asyncua)
Análise de suítes TLS    →    Análise de certificados X.509 OPC UA
```

---

## Motivação

Ferramentas clássicas de análise de segurança, como o SSLyze, não suportam nativamente o protocolo OPC UA — amplamente utilizado em ambientes de automação industrial (Indústria 4.0). Ao executar o SSLyze padrão contra um servidor OPC UA, o scanner falha com a mensagem:

```
=> ERROR: TLS probing failed: could not find a TLS version and cipher suite
   supported by the server; discarding scan.
```

Este projeto resolve essa limitação, permitindo que a lógica de análise de certificados do SSLyze seja reaproveitada para contextos industriais baseados em OPC UA.

---

## Arquitetura das Modificações

Dois arquivos do código-fonte do SSLyze foram alterados:

### `sslyze/server_connectivity.py`

A função `check_connectivity_to_server()` foi substituída por uma verificação de conectividade via **socket TCP simples**, testando apenas se a porta do servidor está acessível:

```python
def check_connectivity_to_server(
    server_location: ServerNetworkLocation,
    network_configuration: ServerNetworkConfiguration
) -> ServerTlsProbingResult:
    import socket
    try:
        sock = socket.create_connection(
            (server_location.hostname, server_location.port),
            timeout=5,
        )
        sock.close()
    except OSError as e:
        raise ConnectionToServerFailed(
            server_location=server_location,
            network_configuration=network_configuration,
            error_message=f"OPC UA connection failed: {e}",
        )
    return ServerTlsProbingResult(
        highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
        cipher_suite_supported="OPC-UA",
        client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
        supports_ecdh_key_exchange=False,
    )
```

### `sslyze/plugins/certificate_info/_get_cert_chain.py`

A função `get_certificate_chain()` foi reescrita para obter o certificado diretamente dos **endpoints OPC UA** usando `asyncua`, em vez de uma conexão nassl/TLS:

```python
async def _get_opcua_certificate(hostname: str, port: int):
    url = f"opc.tcp://{hostname}:{port}"
    client = Client(url=url, timeout=5)
    try:
        endpoints = await client.connect_and_get_server_endpoints()
    except Exception as e:
        raise ConnectionError(f"Falha ao obter endpoints OPC UA: {e}") from e

    for ep in endpoints:
        cert_der = bytes(ep.ServerCertificate)
        if cert_der and len(cert_der) > 0:
            return x509.load_der_x509_certificate(cert_der, default_backend())

    raise ValueError("Nenhum certificado encontrado nos endpoints do servidor OPC UA.")
```

---

## Pré-requisitos

- **Python 3.12** (versões mais recentes apresentam incompatibilidades com `asyncua`)
- **Git**
- **winget** (Windows) ou equivalente para instalação do Python
- Servidor OPC UA em execução (ex.: [Prosys OPC UA Simulation Server](https://prosysopc.com/products/opc-ua-simulation-server/))

---

## Instalação e Configuração

### 1. Clone o repositório

```bash
git clone https://github.com/allanss1lva/sslyze-opcua-2.0
cd sslyze-opcua-2.0
```

### 2. Instale o Python 3.12

```bash
winget install Python.Python.3.12
```

### 3. Crie e ative o ambiente virtual

```bash
py -3.12 -m venv venv
venv\Scripts\activate.bat
```

### 4. Instale as dependências

```bash
pip install --upgrade pip setuptools wheel
pip install -e .
pip install asyncua
```

---

## Uso

Com o servidor OPC UA em execução, execute:

```bash
sslyze --certinfo <HOSTNAME_OU_IP>:<PORTA>
```

**Exemplo:**

```bash
sslyze --certinfo PC0283:53530
```

> Substitua `PC0283:53530` pelo endereço e porta do seu servidor OPC UA (visível na aba **Status** do Prosys ou equivalente).

---

## Resultados Esperados

Uma execução bem-sucedida retorna informações do certificado X.509 do servidor, por exemplo:

```
SCAN RESULTS FOR PC0283:53530
─────────────────────────────────────────────────────

* Certificates Information:
    Hostname sent for SNI:              PC0283
    Number of cert chains detected:     1 (RSAPublicKey)

    Certificate Chain #1 (RSAPublicKey, SNI enabled)
        SHA1 Fingerprint:       ee2a927719d926982109424c8fef88ead59d5d06
        Common Name:            SimulationServer@PC0283
        Issuer:                 SimulationServer@PC0283
        Serial Number:          1773689176746
        Not Before:             2026-03-16
        Not After:              2036-03-13
        Public Key Algorithm:   RSAPublicKey
        Signature Algorithm:    sha256
        Key Size:               2048
        SubjAltName - DNS Names: ['PC0283']

SCANS COMPLETED IN 0.300622 S
```

---

## Validação

A correção dos dados extraídos pode ser verificada comparando o **número de série** retornado pelo SSLyze com o exibido na aba **Certificates** do Prosys (ou equivalente). No exemplo acima:

| Fonte      | Número de Série (hex) | Número de Série (decimal) |
|------------|-----------------------|---------------------------|
| SSLyze     | `019cf81d02aa`        | `1773689176746`           |
| Prosys     | `019cf81d02aa`        | `1773689176746`           |

Os valores coincidem, confirmando a extração correta do certificado.

---

## Limitações Conhecidas

- O certificado extraído é **auto-assinado** (Self Signed), portanto não será validado pelas lojas de certificados do sistema operacional (Android, Apple, Java, Mozilla, Windows). Isso é esperado em ambientes OPC UA industriais.

---

## v2.0 — Validação por Política Configurável

A versão 2.0 introduz um subsistema completo de **validação de certificados OPC UA baseado em política**, integrado diretamente ao pipeline do SSLyze. O scanner agora não apenas extrai o certificado, mas o avalia automaticamente contra um conjunto de regras de segurança configuráveis.

---

### Novos Arquivos

| Arquivo | Função |
|---|---|
| `sslyze/plugins/certificate_info/_opcua_validator.py` | Motor de validação com regras e modelo de política |
| `sslyze/scanner/opcua_validation_observer.py` | Observer que integra a validação ao ciclo do scanner |
| `policies/default_opcua_policy.json` | Política padrão em JSON, editável pelo usuário |

---

### Como Funciona

Ao executar `sslyze --certinfo`, o sistema detecta automaticamente o arquivo `policies/default_opcua_policy.json`. Se ele existir, o `OpcuaValidationObserver` é registrado no scanner e passa a:

1. Interceptar o certificado extraído de cada servidor ao final do scan
2. Executar todas as regras da política sobre o certificado
3. Salvar um relatório detalhado em `opcua_validation_report.json`
4. Exibir um resumo formatado no terminal ao final da execução

Nenhum argumento adicional é necessário — a ativação é automática.

---

### Regras de Validação Disponíveis

| ID da Regra | Severidade | O que verifica |
|---|---|---|
| `SELF_SIGNED` | WARNING | Se o certificado é autoassinado e se a política permite |
| `NOT_EXPIRED` | ERROR | Se o certificado está dentro da validade |
| `NOT_YET_VALID` | ERROR | Se a data de início já foi atingida |
| `MAX_VALIDITY` | WARNING | Se a validade total excede o limite configurado |
| `KEY_SIZE` | ERROR | Tamanho mínimo da chave RSA (padrão: 2048 bits) |
| `SIG_ALGORITHM` | ERROR | Se o algoritmo de assinatura está na lista permitida |
| `BASIC_CONSTRAINTS` | ERROR | Presença da extensão `BasicConstraints` com `CA=False` |
| `KEY_USAGE` | WARNING | Bits `digitalSignature` e `keyEncipherment` no `KeyUsage` |
| `EXTENDED_KEY_USAGE` | WARNING | OIDs `serverAuth` / `clientAuth` no `ExtendedKeyUsage` |
| `SAN_URI` | WARNING | Presença de URI `urn:...` no `SubjectAltName` (ApplicationUri OPC UA) |
| `CRL_DISTRIBUTION_POINTS` | WARNING | Presença de ponto de distribuição de CRL |
| `CRITICAL_EXTENSIONS` | WARNING | Se `BasicConstraints` e `KeyUsage` estão marcadas como `critical` |

---

### Política Padrão (`policies/default_opcua_policy.json`)

```json
{
  "allow_self_signed": true,
  "max_validity_days": 365,
  "min_rsa_key_size": 2048,
  "allowed_signature_algorithms": ["sha256", "sha384", "sha512"],
  "require_basic_constraints": true,
  "require_key_usage": true,
  "require_digital_signature": true,
  "require_key_encipherment": true,
  "require_extended_key_usage": true,
  "require_server_auth": true,
  "require_client_auth": false,
  "require_san_uri": true,
  "require_crl_distribution_points": false
}
```

Para criar uma política customizada, edite este arquivo ou aponte para outro via código. Todos os campos são opcionais — valores não informados assumem os padrões definidos em `OpcuaPolicyConfig`.

---

### Exemplo de Saída v2.0

Ao final do scan, uma seção adicional é exibida no terminal:

```
 * Validação OPC UA v2.0
   ────────────────────────────────────────────────────────────

   Servidor  : PC0283:53530
   Resultado : APROVADO COM AVISOS  |  Erros: 0  |  Avisos: 3

   [OK   ] [WARNING] SELF_SIGNED            OK
   [OK   ] [ERROR  ] NOT_EXPIRED            Válido até 2036-03-13
   [OK   ] [ERROR  ] NOT_YET_VALID          OK
   [FALHA] [WARNING] MAX_VALIDITY           Validade de 3650 dias excede o limite de 365 dias
   [OK   ] [ERROR  ] KEY_SIZE               Chave RSA de 2048 bits
   [OK   ] [ERROR  ] SIG_ALGORITHM          Algoritmo 'sha256' permitido
   [OK   ] [ERROR  ] BASIC_CONSTRAINTS      BasicConstraints presente e CA=False
   [OK   ] [WARNING] KEY_USAGE              KeyUsage presente com bits obrigatórios
   [FALHA] [WARNING] EXTENDED_KEY_USAGE     OIDs obrigatórios ausentes no ExtendedKeyUsage: serverAuth
   [FALHA] [WARNING] SAN_URI               SubjectAltName não contém URI OPC UA (urn:...)
   [OK   ] [WARNING] CRL_DISTRIBUTION_POINTS  CRLDistributionPoints ausente (não obrigatória pela política)
   [OK   ] [WARNING] CRITICAL_EXTENSIONS   BasicConstraints e KeyUsage marcadas como critical

   Relatório JSON salvo em: opcua_validation_report.json
```

O resultado `APROVADO` indica zero erros (nenhuma regra `ERROR` falhou). Avisos (`WARNING`) são informativos e não reprovam o certificado, mas sinalizam pontos de atenção para adequação às boas práticas OPC UA.

---

## Referências

- [SSLyze — repositório original](https://github.com/nabla-c0d3/sslyze)
- [asyncua — Python OPC UA library](https://github.com/FreeOpcUa/opcua-asyncio)
- [Prosys OPC UA Simulation Server](https://prosysopc.com/products/opc-ua-simulation-server/)
- UFCG, *Explorando SSLyze: Etapa 1 a 8*, Campina Grande, Abril de 2026.
