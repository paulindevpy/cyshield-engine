import os
import sys
from typing import Any, Dict, List
import yaml

LOG_TAG = "[CONFIG:LOADER]"


def print_log(msg: str) -> None:
    """Padronização de logs do sistema."""
    print(f"{LOG_TAG} {msg}")


def get_default_config() -> Dict[str, Any]:
    """Retorna a configuração padrão caso o arquivo não exista ou precise de fallbacks."""
    return {
        "concurrency": {
            "max_hosts": 5,
            "max_dns_threads": 50,
            "max_http_requests": 10,
        },
        "timeouts": {
            "http_seconds": 10,
            "nuclei_seconds": 600,
        },
        "wordlists": {
            "subdomains": [
                "www",
                "mail",
                "remote",
                "blog",
                "webmail",
                "server",
                "ns1",
                "ns2",
                "smtp",
                "secure",
                "vpn",
                "api",
                "dev",
                "staging",
            ],
            "permutations": ["dev", "stg", "prod", "test", "stage", "app"],
        },
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        ],
        "nuclei": {
            "min_severity": "low",
            "flags": ["-silent", "-nc"],
        },
    }


def validate_config(config: Dict[str, Any]) -> None:
    """Valida o schema, tipos de dados e limites do dicionário de configuração."""
    try:
        # 1. Validação de Concorrência
        concurrency = config.get("concurrency", {})
        if not isinstance(concurrency, dict):
            raise TypeError("Seção 'concurrency' deve ser um dicionário.")

        for key in ["max_hosts", "max_dns_threads", "max_http_requests"]:
            val = concurrency.get(key)
            if not isinstance(val, int) or val <= 0:
                raise ValueError(
                    f"Configuração 'concurrency.{key}' deve ser um inteiro > 0. Valor atual: {val}"
                )

        # 2. Validação de Timeouts
        timeouts = config.get("timeouts", {})
        if not isinstance(timeouts, dict):
            raise TypeError("Seção 'timeouts' deve ser um dicionário.")

        for key in ["http_seconds", "nuclei_seconds"]:
            val = timeouts.get(key)
            if not isinstance(val, (int, float)) or val <= 0:
                raise ValueError(
                    f"Configuração 'timeouts.{key}' deve ser um número maior que 0. Valor atual: {val}"
                )

        # 3. Validação de Wordlists
        wordlists = config.get("wordlists", {})
        if not isinstance(wordlists, dict):
            raise TypeError("Seção 'wordlists' deve ser um dicionário.")

        for key in ["subdomains", "permutations"]:
            val = wordlists.get(key)
            if not isinstance(val, list) or not all(
                isinstance(item, str) for item in val
            ):
                raise ValueError(
                    f"Configuração 'wordlists.{key}' deve ser uma lista de strings válidas."
                )

        # 4. Validação de User-Agents
        user_agents = config.get("user_agents", [])
        if not isinstance(user_agents, list) or not all(
            isinstance(ua, str) for ua in user_agents
        ):
            raise ValueError(
                "Configuração 'user_agents' deve ser uma lista contendo strings (User-Agents)."
            )

        # 5. Validação de Nuclei
        nuclei = config.get("nuclei", {})
        if not isinstance(nuclei, dict):
            raise TypeError("Seção 'nuclei' deve ser um dicionário.")

        severities = ["info", "low", "medium", "high", "critical"]
        min_sev = nuclei.get("min_severity")
        if min_sev not in severities:
            raise ValueError(
                f"Configuração 'nuclei.min_severity' deve ser uma das opções: {severities}. Valor atual: '{min_sev}'"
            )

    except (ValueError, TypeError) as e:
        print_log(f"Erro de validação no schema do YAML: {type(e).__name__} - {e}")
        raise


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Carrega o arquivo YAML de configuração, aplica defaults em dados ausentes e valida a estrutura final."""
    defaults = get_default_config()

    if not os.path.exists(config_path):
        print_log(
            f"Arquivo '{config_path}' não encontrado. Carregando configurações padrão (defaults)."
        )
        return defaults

    try:
        print_log(f"Carregando arquivo de configuração: {config_path}")
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}

        # Merge de 2 níveis para garantir fallbacks caso chaves parciais faltem
        merged_config = defaults.copy()
        for key, value in user_config.items():
            if isinstance(value, dict) and key in merged_config:
                merged_config[key].update(value)
            else:
                merged_config[key] = value

        # Validação do Schema
        validate_config(merged_config)
        print_log("Configuração carregada e validada com sucesso.")
        return merged_config

    except yaml.YAMLError as e:
        print_log(
            f"Erro na sintaxe YAML do arquivo '{config_path}': {type(e).__name__} - {e}"
        )
        sys.exit(1)
    except Exception as e:
        print_log(
            f"Falha ao carregar a configuração: {type(e).__name__} - {e}"
        )
        sys.exit(1)


if __name__ == "__main__":
    # Teste de execução direta do módulo
    print_log("Executando teste local do carregador de configurações...")
    cfg = load_config("config.yaml")
    print(f"Resultado do Config Load:\n{cfg}")
