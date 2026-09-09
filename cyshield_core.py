import argparse
import json
import sys
import os
import socket
from datetime import datetime
from recon import map_subdomains  # Mantenha o nome exato da função do seu recon.py
from portscan import scanner_ports
from vulnscan import scanner_vuln
from ai_reports import general_report_executive


def save_report(domain, dados_json, reports_ia=None):
    """Salva os resultados em arquivos físicos na pasta reports/"""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = f"reports/{domain}_{timestamp}"


    #### Saved JSON bruto
    json_path = f"{base_filename}.json"
    with open(json_path, "w", encoding="utf-8") as f:
         json.dump(dados_json, f, indent=4, ensure_ascii=False)
    print(f"\n[+] Relatório JSON bruto salvo em: {json_path}")

    #### Salve relatório em Markdown se a IA tiver gerado
    if reports_ia:
       md_path = f"{base_filename}_Executive.md"
       with open(md_path, "w", encoding="utf-8") as f:
            f.write(reports_ia)
       print(f"[+] Relatório Executivo (IA) salvo em: {md_path}")

def run_pipeline_cyshield(domains_target, api_key_claude=None):
    print("=" * 65)
    print(f"[CYSHIELD CORE] INICIANDO PIPELINE DE DEFESA: {domains_target}")
    print("=" * 65)

    wordlist_subs = ["www", "api", "dev", "mail", "admin"]
    ports_target = [21, 22, 80, 443, 3306, 8080]

    # ETAPA 1: Reconhecimento de Subdomínios (OSINT)
    print("[ETAPA 1/3] Mapeando subdomínios e infraestrutura...")
    subdomains_found = map_subdomains(domains_target, wordlist_subs)

    # Tenta resolver o próprio alvo principal caso nenhum subdomínio da wordlist responda
    try:
        main_ip = socket.gethostbyname(domains_target)
        subdomains_found[domains_target] = main_ip
    except socket.gaierror:
        pass

    general_report = {
        "domain": domains_target,
        "timestamp": datetime.now().isoformat(),
        "total_subdomains_actives": len(subdomains_found),
        "actives": {}
    }

    # ETAPA 2 & 3: Mapeamento de Portas e Vulnerabilidades
    print("\n[ETAPA 2/3 & 3/3] Escaneando portas e buscando vulnerabilidades...")

    for sub, ip in subdomains_found.items():
        print(f"\n---> Analisando Host: {sub} ({ip})")

        # Módulo PortScan
        open_ports = scanner_ports(ip, ports_target)

        # Módulo VulnScan
        url_target = f"http://{sub}"
        failed = scanner_vuln(url_target)

        # Consolidação da estrutura de dados em formato JSON
        general_report["actives"][sub] = {
            "ip": ip,
            "open_ports": open_ports,
            "vulnerabilities": failed
        }


        #### ETAPA 4: Inteligência Artificial
        reports_ia = None
        if api_key_claude:
           reports_ia = general_report_executive(general_report, api_key_claude)


        #### Exportação física para o disco
        save_report(domains_target, general_report, reports_ia)

        return general_report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CySHield Engine - Pipeline Automatizada de Cibersegurança"
    )
        #### Adiciona a opção de passar o alvo (-t ou --target)
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Domínio ou IP do alvo (ex: scanme.nmap.org)"
    )
        #### REGISTRA A FLAG --ai 
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Ativa a geração de rlatório executivo via API do Claude"

    )
        #### Lê os argumentos passados pelo terminal 
    args = parser.parse_args()

    CLAUDE_KEY = None
    if args.ai:
         ####  API CLAUDE
        CLAUDE_KEY = os.getenv("ANTHROPIC_API_KEY", "")
        if not CLAUDE_KEY:
            print("[!] AVISO: ANTHROPIC_API_KEY não definida no ambiente.")


    run_pipeline_cyshield(args.target, api_key_claude=CLAUDE_KEY)
