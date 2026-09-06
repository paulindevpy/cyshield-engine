import json
import sys
import socket
from recon import map_subdomains  # Mantenha o nome exato da função do seu recon.py
from portscan import scanner_ports
from vulnscan import scanner_vuln

def run_pipeline_cyshield(domains_target):
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

    return general_report

if __name__ == "__main__":
    target = "testphp.vulnweb.com"

    final_result = run_pipeline_cyshield(target)
    print("\n" + "=" * 65)
    print("[CYSHIELD CORE] PIPELINE CONCLUÍDA - RELATÓRIO FINAL (JSON)")
    print("=" * 65)
    print(json.dumps(final_result, indent=4))
