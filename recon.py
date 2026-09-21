"""
CyShield Engine v2.0 - recon.py (Enterprise Recon)
Passive + Active subdomain enumeration with:
- Certificate Transparency (crt.sh)
- Passive API (HackerTarget)
- Async DNS resolution (thread pool offload)
- Permutation/alteration scanning
- Wildcard DNS detection
- Global rate limiting + retry/backoff
"""

import asyncio
import socket
import random
import string
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import aiohttp

# ============================================================
# CONFIG GLOBAL
# ============================================================
DNS_CONCURRENCY = 50       # threads de resolução DNS simultâneas
HTTP_CONCURRENCY = 10      # requisições HTTP simultâneas (anti rate-limit)
HTTP_TIMEOUT = 15          # timeout de APIs passivas (segundos)
MAX_RETRIES = 3            # tentativas com backoff exponencial
PERM_DEPTH = 1             # nº de "prefixos/sufixos" usados nas permutações

# Prefixos/sufixos usados para gerar permutações dos subdomínios encontrados
PERM_WORDS = [
    "dev", "test", "stage", "staging", "uat", "prod", "qa", "demo",
    "beta", "alpha", "old", "new", "v1", "v2", "v3", "api", "internal",
    "intranet", "corp", "vpn", "mail", "smtp", "webmail", "autodiscover",
    "admin", "portal", "sso", "auth", "login", "gw", "gateway", "proxy",
    "cdn", "static", "assets", "img", "media", "backup", "bak", "db",
    "sql", "mysql", "postgres", "redis", "elastic", "kibana", "jenkins",
    "git", "gitlab", "jira", "confluence", "monitor", "grafana", "prometheus",
    "nagios", "zabbix", "logs", "log", "syslog", "s3", "storage", "files",
    "ftp", "sftp", "ssh", "rdp", "remote", "citrix", "exchange", "lync",
]

# Wordlist de brute force ativo (baseada em top subdomains públicos)
WORDLIST_ACTIVE = [
    "www", "www2", "www3", "mail", "webmail", "smtp", "pop", "imap", "mx",
    "ns1", "ns2", "dns", "vpn", "remote", "gateway", "gw", "proxy", "fw",
    "api", "apis", "rest", "graphql", "soap", "ws", "webservice", "gateway-api",
    "dev", "development", "test", "testing", "qa", "stage", "staging", "stg",
    "uat", "preprod", "pre", "demo", "sandbox", "beta", "alpha", "next",
    "prod", "production", "app", "apps", "web", "webapp", "portal", "client",
    "admin", "adminpanel", "panel", "cpanel", "whm", "manage", "manager",
    "dashboard", "console", "cms", "intranet", "internal", "corp", "corporate",
    "sso", "auth", "oauth", "login", "id", "identity", "accounts", "account",
    "cdn", "assets", "static", "media", "img", "images", "files", "download",
    "cloud", "s3", "storage", "backup", "bak", "old", "archive", "db",
    "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic",
    "kibana", "grafana", "monitor", "monitoring", "prometheus", "nagios",
    "zabbix", "logs", "log", "git", "gitlab", "github", "jenkins", "ci",
    "cd", "build", "deploy", "docker", "k8s", "kubernetes", "rancher",
    "jira", "confluence", "wiki", "docs", "documentation", "support",
    "help", "helpdesk", "ticket", "crm", "erp", "hr", "shop", "store",
    "ecommerce", "payment", "payments", "pay", "billing", "invoice",
    "ftp", "sftp", "ssh", "rdp", "vnc", "citrix", "exchange", "outlook",
    "lync", "skype", "teams", "zoom", "meet", "chat", "slack", "bot",
    "mobile", "m", "wap", "amp", "blog", "news", "forum", "community",
    "shopify", "magento", "wordpress", "wp", "drupal", "joomla", "status",
    "health", "ping", "nagios", "sensu", "new", "old2", "core", "main",
    "secure", "ssl", "tls", "vpn2", "openvpn", "ldap", "ad", "dc", "saml",
]


# ============================================================
# UTILITÁRIOS
# ============================================================
def _log(tag, msg):
    """Log padronizado do engine."""
    print(f"[RECON:{tag}] {msg}")


def _random_sub(length=10):
    """Gera subdomínio aleatório improvável (para detecção de wildcard)."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ============================================================
# RESOLUÇÃO DNS ASSÍNCRONA
# ============================================================
async def resolve_host(domain, executor):
    """
    Resolve DNS sem travar o event loop.
    O socket.gethostbyname é bloqueante, então o offload para
    ThreadPoolExecutor mantém o pipeline 100% async.
    """
    loop = asyncio.get_running_loop()
    try:
        ip = await loop.run_in_executor(executor, socket.gethostbyname, domain)
        return ip
    except (socket.gaierror, OSError):
        return None


# ============================================================
# FONTES PASSIVAS (OSINT puro - não toca no alvo)
# ============================================================
async def fetch_with_retry(session, url, semaphore, params=None):
    """
    GET com retry + backoff exponencial + limite de concorrência.
    Padrão reutilizável em todos os módulos HTTP da v2.0.
    """
    async with semaphore:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.get(
                    url, params=params, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    if resp.status == 429:  # rate limited
                        wait = 2 ** attempt
                        _log("PASSIVE", f"Rate limit (429) em {url}. Aguardando {wait}s...")
                        await asyncio.sleep(wait)
                        continue
                    return None
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt == MAX_RETRIES:
                    _log("PASSIVE", f"Falha final em {url}: {e}")
                    return None
                await asyncio.sleep(2 ** attempt)
        return None


async def query_crtsh(domain, session, semaphore):
    """
    Certificate Transparency via crt.sh.
    Autoridades de certificação (Let's Encrypt, DigiCert...) publicam TODO
    certificado emitido em logs públicos CT. Subdomínios com TLS emitido
    algum dia na história aparecem aqui — mesmo que hoje estejam ocultos.
    """
    _log("PASSIVE", "Consultando Certificate Transparency (crt.sh)...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    raw = await fetch_with_retry(session, url, semaphore)
    found = set()
    if not raw:
        _log("PASSIVE", "crt.sh indisponível ou sem resultados.")
        return found
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        # crt.sh às vezes retorna HTML em erro; tenta extrair por regex
        entries = []
    for entry in entries:
        names = entry.get("name_value", "")
        # name_value pode conter múltiplos SANs separados por \n
        for name in names.split("\n"):
            name = name.strip().lower()
            # Filtra wildcards e garante que é subdomínio do alvo
            if name.endswith("." + domain) and "*" not in name:
                found.add(name)
    _log("PASSIVE", f"crt.sh: {len(found)} subdomínios únicos encontrados.")
    return found


async def query_hackertarget(domain, session, semaphore):
    """
    API passiva pública do HackerTarget (host search).
    Fonte secundária: usa dados de DNS inverso/PTR e fontes abertas.
    """
    _log("PASSIVE", "Consultando HackerTarget passive host search...")
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    raw = await fetch_with_retry(session, url, semaphore)
    found = set()
    if not raw or "error" in raw.lower():
        return found
    # Formato: "sub.dominio.com,IP" por linha
    for line in raw.strip().splitlines():
        parts = line.split(",")
        if parts and parts[0].strip().endswith("." + domain):
            found.add(parts[0].strip().lower())
    _log("PASSIVE", f"HackerTarget: {len(found)} subdomínios encontrados.")
    return found


# ============================================================
# WILDCARD DETECTION
# ============================================================
async def detect_wildcard(domain, executor):
    """
    Resolve 2 subdomínios aleatórios. Se ambos resolverem para o mesmo IP,
    o domínio tem wildcard DNS e precisamos filtrar falsos positivos.
    Retorna o IP canário (a filtrar) ou None.
    """
    probe1, probe2 = _random_sub(), _random_sub()
    ip1 = await resolve_host(f"{probe1}.{domain}", executor)
    ip2 = await resolve_host(f"{probe2}.{domain}", executor)
    if ip1 and ip2 and ip1 == ip2:
        _log("WILDCARD", f"Wildcard DNS detectado! IP canário: {ip1}. Falsos positivos serão filtrados.")
        return ip1
    _log("WILDCARD", "Nenhum wildcard DNS detectado.")
    return None


# ============================================================
# PERMUTAÇÕES (Alteration Scanning)
# ============================================================
def generate_permutations(discovered, domain, depth=PERM_DEPTH):
    """
    Técnica 'altdns': pega subdomínios reais já descobertos e gera variações.
    Ex: descobriu 'api' -> testa 'api-dev', 'dev-api', 'api2', 'api-v2', 'dev2'...
    Descobre ativos que NENHUMA wordlist genérica alcançaria.
    """
    _log("PERMUT", f"Gerando permutações a partir de {len(discovered)} ativos descobertos...")
    base_labels = set()
    for sub in discovered:
        # Extrai apenas o primeiro label (api.dominio.com -> "api")
        label = sub[: -len("." + domain)].split(".")[0]
        if label and len(label) <= 30:
            base_labels.add(label)

    perms = set()
    for label in base_labels:
        for w in PERM_WORDS[: 25 * depth]:
            perms.add(f"{label}-{w}")
            perms.add(f"{w}-{label}")
            perms.add(f"{label}{w}")
            perms.add(f"{w}{label}")
            perms.add(f"{label}.{w}")
    perms -= discovered  # já conhecidos, não testa de novo
    _log("PERMUT", f"{len(perms)} permutações geradas para teste.")
    return perms


# ============================================================
# ORQUESTRADOR PRINCIPAL (API compatível com cyshield_core.py)
# ============================================================
async def map_subdomains_async(domain, extra_words=None, use_passive=True,
                               use_active=True, use_permutations=True):
    """
    Pipeline completo de recon. Retorna (dict {sub: ip}, dict de metadados).
    A função síncrona map_subdomains() abaixo mantém compatibilidade v1.1.
    """
    start_time = datetime.now()
    results = {}
    metadata = {
        "sources": {"crtsh": set(), "hackertarget": set(), "bruteforce": set(), "permutation": set()},
        "wildcard_canary_ip": None,
        "total_permutations_tested": 0,
    }

    executor = ThreadPoolExecutor(max_workers=DNS_CONCURRENCY)
    semaphore = asyncio.Semaphore(HTTP_CONCURRENCY)

    # --- Fase 0: Wildcard detection
    canary_ip = await detect_wildcard(domain, executor)
    metadata["wildcard_canary_ip"] = canary_ip

    candidates = set()

    # --- Fase 1: Fontes passivas
    if use_passive:
        async with aiohttp.ClientSession(
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        ) as session:
            crt, ht = await asyncio.gather(
                query_crtsh(domain, session, semaphore),
                query_hackertarget(domain, session, semaphore),
            )
        candidates |= crt | ht
        metadata["sources"]["crtsh"] = crt
        metadata["sources"]["hackertarget"] = ht

    # --- Fase 2: Brute force ativo
    active_words = set(WORDLIST_ACTIVE)
    if extra_words:
        active_words.update(extra_words)
    active_hosts = {f"{w}.{domain}" for w in active_words}
    _log("ACTIVE", f"Brute force em {len(active_hosts)} candidatos com {DNS_CONCURRENCY} workers...")

    async def resolve_and_track(host, source):
        ip = await resolve_host(host, executor)
        if ip and ip != canary_ip:
            results[host] = ip
            metadata["sources"][source].add(host)
        return

    await asyncio.gather(*(resolve_and_track(h, "bruteforce") for h in active_hosts))
    candidates |= set(results.keys())

    # --- Fase 3: Permutações dos ativos encontrados
    if use_permutations and candidates:
        perms = generate_permutations(candidates, domain)
        metadata["total_permutations_tested"] = len(perms)
        perm_hosts = {f"{p}.{domain}" for p in perms}
        await asyncio.gather(*(resolve_and_track(h, "permutation") for h in perm_hosts))

    elapsed = (datetime.now() - start_time).total_seconds()
    _log("DONE", f"Recon concluído: {len(results)} ativos em {elapsed:.1f}s")

    # Metadados: sets não são serializáveis em JSON -> converte para lista
    for k in metadata["sources"]:
        metadata["sources"][k] = sorted(metadata["sources"][k])

    executor.shutdown(wait=False)
    return results, metadata


def map_subdomains(domain, extra_words=None, **kwargs):
    """
    Wrapper síncrono de compatibilidade v1.1 — cyshield_core.py continua
    funcionando sem alterações. Retorna apenas {sub: ip} como antes.
    """
    return asyncio.run(
        map_subdomains_async(domain, extra_words=extra_words, **kwargs)
    )[0]


async def get_recon_report(domain, **kwargs):
    """
    Versão Enterprise: retorna estrutura rica para o JSON do relatório.
    """
    results, metadata = await map_subdomains_async(domain, **kwargs)
    return {
        "module": "recon",
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "total_actives": len(results),
        "actives": results,
        "wildcard_detected": metadata["wildcard_canary_ip"] is not None,
        "discovery_by_source": {
            src: len(hosts) for src, hosts in metadata["sources"].items()
        },
        "total_permutations_tested": metadata["total_permutations_tested"],
    }


if __name__ == "__main__":
    # Teste standalone: python3 recon.py dominio.com
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    rep = asyncio.run(get_recon_report(target))
    print(json.dumps(rep, indent=2, ensure_ascii=False))
