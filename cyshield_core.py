"""
CyShield Engine v2.0 Enterprise - cyshield_core.py
Pipeline assíncrono completo:
  ETAPA 1: Recon Enterprise (passivo + ativo + permutações)
  ETAPA 2: PortScan + VulnScan + WebIntel (hosts em paralelo)
  ETAPA 3: Cloud Recon (buckets + JS intelligence)
  ETAPA 4: Relatório IA (Claude) + Exportação JSON/MD/PDF
  ETAPA 5: Notificação Discord
"""

import argparse
import asyncio
import json
import sys
import os
import socket
from datetime import datetime

from recon import map_subdomains_async
from portscan import scanner_ports
from vulnscan import scanner_vuln
from websearch import analyze_host
from cloud_recon import run_cloud_recon
from ai_reports import generate_ai_report, convert_md_to_pdf
from notifications import send_discord_webhook_v2
from diff_engine import attach_diff_if_available
from config_loader import load_config
from storage import init_db, save_scan


HOST_CONCURRENCY = 5   # hosts escaneados simultaneamente (protege o alvo)


def save_report(domain, dados_json, reports_ia=None):
    """Salva resultados físicos em reports/ com timestamp."""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"reports/{domain}_{timestamp}"

    json_path = f"{base}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dados_json, f, indent=4, ensure_ascii=False)
    print(f"[CORE] Relatório JSON bruto salvo em: {json_path}")

    pdf_path = None
    if reports_ia:
        md_path = f"{base}_Executive.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(reports_ia)
        print(f"[CORE] Relatório Executivo (IA) salvo em: {md_path}")

        pdf_path = f"{base}_Executive.pdf"
        if not convert_md_to_pdf(reports_ia, pdf_path):
            pdf_path = None
    else:
        print("[CORE] Relatório de IA não gerado (sem --ai ou falha na API).")

    return json_path, pdf_path


def count_criticals(report):
    """Contabiliza achados críticos/high em todo o schema v2 (para métricas)."""
    counts = {"critical": 0, "high": 0}
    for sub, data in report.get("actives", {}).items():
        web = data.get("web_intel") or {}
        for ep in web.get("sensitive_endpoints", []):
            if ep.get("severity") in counts:
                counts[ep["severity"]] += 1
        for v in data.get("vulnerabilities", []):
            info = v.get("info", {})
            if isinstance(info, list) and info:
                info = info[0]
            sev = str(info.get("severity", "")).lower() if isinstance(info, dict) else ""
            if sev in counts:
                counts[sev] += 1
    cloud = report.get("cloud_recon", {})
    for item in cloud.get("buckets_analyzed", []) + cloud.get("js_intelligence", []):
        if item.get("severity") in counts:
            counts[item["severity"]] += 1
    return counts


async def run_pipeline_cyshield(domains_target, api_key_claude=None, webhook_url=None, max_hosts=5):
    print("=" * 65)
    print(f"[CYSHIELD v2.0 ENTERPRISE] PIPELINE INICIADO: {domains_target}")
    print("=" * 65)

    start = datetime.now()
    ports_target = [21, 22, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200]

    general_report = {
        "engine": "CyShield Engine",
        "version": "2.0-enterprise",
        "domain": domains_target,
        "timestamp": start.isoformat(),
    }

    # ---------- ETAPA 1: RECON ENTERPRISE ----------
    print("\n[ETAPA 1/4] Recon Enterprise: crt.sh + passive + brute force + permutações...")
    try:
        subdomains_found, recon_meta = await map_subdomains_async(domains_target)
    except Exception as e:
        print(f"[CORE] Falha no recon ({e}). Fallback: alvo principal apenas.")
        subdomains_found, recon_meta = {}, {}
        try:
            subdomains_found[domains_target] = socket.gethostbyname(domains_target)
        except socket.gaierror:
            print("[CORE] ERRO FATAL: nem o domínio principal resolve. Encerrando.")
            return None

    if domains_target not in subdomains_found:
        try:
            subdomains_found[domains_target] = socket.gethostbyname(domains_target)
        except socket.gaierror:
            pass

    general_report["recon"] = {
        "total_actives": len(subdomains_found),
        "wildcard_detected": recon_meta.get("wildcard_canary_ip") is not None,
        "discovery_by_source": {
            src: len(hosts) for src, hosts in recon_meta.get("sources", {}).items()
        },
        "total_permutations_tested": recon_meta.get("total_permutations_tested", 0),
    }
    print(f"[CORE] ETAPA 1 concluída: {len(subdomains_found)} ativos.")

    # ---------- ETAPA 2: SCAN POR HOST (PARALELO) ----------
    print(f"\n[ETAPA 2/4] PortScan + VulnScan + WebIntel (paralelismo={HOST_CONCURRENCY})...")
    general_report["actives"] = {}
    host_semaphore = asyncio.Semaphore(max_hosts)
    loop = asyncio.get_running_loop()

    async def process_host(sub, ip):
        async with host_semaphore:
            print(f"  [HOST] {sub} ({ip}) iniciando...")
            open_ports = await scanner_ports(ip, ports_target)

            # nuclei é subprocess bloqueante -> executor
            vulns = []
            for scheme in ("http", "https"):
                r = await loop.run_in_executor(None, scanner_vuln, f"{scheme}://{sub}")
                if r:
                    vulns.extend(r)
                    break

            # web intel (async nativo), tenta HTTPS se HTTP falhar
            web_result = await analyze_host(f"http://{sub}")
            if web_result is None:
                web_result = await analyze_host(f"https://{sub}")

            general_report["actives"][sub] = {
                "ip": ip,
                "open_ports": open_ports,
                "vulnerabilities": vulns,
                "web_intel": web_result,
            }
            print(f"  [HOST] {sub} concluído: {len(open_ports)} portas | "
                  f"{len(vulns)} vulns | {len((web_result or {}).get('sensitive_endpoints', []))} endpoints sensíveis")

    await asyncio.gather(*(process_host(s, i) for s, i in subdomains_found.items()))
    print(f"[CORE] ETAPA 2 concluída: {len(general_report['actives'])} hosts processados.")

    # ---------- ETAPA 3: CLOUD RECON ----------
    print("\n[ETAPA 3/4] Cloud Recon: buckets S3/GCS/Azure + parsing de JavaScript...")
    js_urls = []
    for sub, data in general_report["actives"].items():
        web = data.get("web_intel") or {}
        js_urls.extend(web.get("js_assets") or [])
    js_urls = list(dict.fromkeys(js_urls))[:25]  # dedup preservando ordem

    try:
        cloud_result = await run_cloud_recon(
            domains_target,
            subdomains=list(subdomains_found.keys()),
            js_urls=js_urls,
        )
    except Exception as e:
        print(f"[CORE] Falha no cloud recon: {e}")
        cloud_result = {"module": "cloud_recon", "error": str(e),
                        "buckets_analyzed": [], "js_intelligence": [],
                        "summary": {"buckets_found": 0, "critical_findings": 0}}

    general_report["cloud_recon"] = cloud_result
    print(f"[CORE] ETAPA 3 concluída: {cloud_result['summary']['buckets_found']} buckets, "
          f"{cloud_result['summary']['critical_findings']} críticos.")

    # ---------- Métricas consolidadas ----------
    general_report["summary"] = {
        "scan_duration_seconds": round((datetime.now() - start).total_seconds(), 1),
        "hosts_scanned": len(general_report["actives"]),
        **count_criticals(general_report),
    }
    print(f"[CORE] Métricas: {json.dumps(general_report['summary'])}")

    # ---------- DIFF HISTÓRICO ----------
    print("\n[ETAPA 3.5] Comparando com scans anteriores (monitoramento contínuo)...")
    attach_diff_if_available(general_report)

    # ---------- ETAPA 4: RELATÓRIO IA + EXPORTAÇÃO ----------
    print("\n[ETAPA 4/4] Relatório IA + exportação + notificação...")
    reports_ia = None
    if api_key_claude:
        reports_ia = await loop.run_in_executor(
            None, generate_ai_report, general_report, api_key_claude
        )
    json_path, pdf_path = save_report(domains_target, general_report, reports_ia)

    # Persistência no banco SQLite
    try:
        await save_scan(general_report)
    except Exception as e:
        print(f"[CORE] Falha ao salvar scan no SQLite: {type(e).__name__} - {e}")


    if webhook_url:
        counts = general_report["summary"]
        send_discord_webhook_v2(
            webhook_url, domains_target,
            total_subs=len(subdomains_found),
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            duration=counts.get("scan_duration_seconds", 0),
            json_path=json_path,
            pdf_path=pdf_path,
        )

    print("=" * 65)
    print(f"[CYSHIELD v2.0] PIPELINE FINALIZADO em {general_report['summary']['scan_duration_seconds']}s")
    print("=" * 65)
    return general_report


def main():
    init_db()
    parser = argparse.ArgumentParser(
        description="CyShield Engine v2.0 Enterprise - Pipeline de Cibersegurança @Paulindev.py"
    )
    config = load_config("config.yaml")
    default_hosts = config.get("concurrency", {}).get("max_hosts", HOST_CONCURRENCY)

    parser.add_argument("-t", "--target", action="append", default=[],
                        help="Domínio alvo (ex: exemplo.com, repita a flag para múltiplos: -t a.com -t b.com)")
    parser.add_argument("--targets-file", type=str,
                        help="Arquivo de texto com um dominio por linha")
    parser.add_argument("--ai", action="store_true",
                        help="Ativa relatório executivo via API do Claude")
    parser.add_argument("--webhook", type=str,
                        help="URL do Webhook do Discord")
    parser.add_argument("--hosts", type=int, default=default_hosts,
                        help=f"Máximo de hosts em paralelo (padrão {default_hosts})")
    args = parser.parse_args()


    targets = list(args.target)
    if args.targets_file:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] Arquivo de alvos não encontrado: {args.targets_file}")
            sys.exit(1)

    if not targets:
        parser.error("Nenhum alvo informado. Use -t ou --targets-file.")

    CLAUDE_KEY = None
    if args.ai:
        CLAUDE_KEY = os.getenv("ANTHROPIC_API_KEY", "")
        if not CLAUDE_KEY:
            print("[!] AVISO: ANTHROPIC_API_KEY não definida no ambiente.")

    results = []
    for target in targets:
        print(f"\n{'#'*65}\n#[ALVO] {target}\n{'#'*65}")
        try:
            r = asyncio.run(run_pipeline_cyshield(
                target, api_key_claude=CLAUDE_KEY, webhook_url=args.webhook,
                max_hosts=args.hosts
            ))
            results.append(r)
        except Exception as e:
            print(f"[!] Falha no alvo {target}: {e} — seguindo para o próximo.")
    sys.exit(0 if any(results) else 1)

if __name__ == "__main__":
    main()
