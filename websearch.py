"""
CyShield Engine v2.0 - websearch.py
Web content discovery & fingerprinting:
- HTTP header analysis & tech fingerprinting (heurístico)
- Sensitive endpoint discovery (/.env, /.git, /swagger.json, etc.)
- Soft-404 filtering (falso positivo reduzido)
- Reusa padrões de recon.py: semaphore, retry, backoff, UA rotation
"""

import asyncio
import random
import re
from datetime import datetime

import aiohttp

# ============================================================
# CONFIG
# ============================================================
HTTP_CONCURRENCY = 15      # requisições simultâneas por host (anti WAF)
REQUEST_TIMEOUT = 12
MAX_RETRIES = 2
DELAY_JITTER = (0.2, 0.8)  # atraso aleatório entre requests (evitação de padrão)

# Rotação de User-Agents (WAFs bloqueiam UA de tools conhecidas)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# Endpoints sensíveis: (caminho, severidade, padrão de conteúdo que confirma o achado)
SENSITIVE_ENDPOINTS = [
    ("/.env",                  "critical", r"(DB_PASSWORD|APP_KEY|AWS_SECRET|SECRET_KEY)="),
    ("/.git/config",           "critical", r"\[core\]"),
    ("/.git/HEAD",             "high",     r"ref: refs/"),
    ("/.env.backup",           "critical", r"(DB_PASSWORD|APP_KEY)="),
    ("/.aws/credentials",      "critical", r"(aws_access_key_id|secret_access_key)"),
    ("/backup.sql",            "high",     r"(CREATE TABLE|INSERT INTO)"),
    ("/db.sql",                "high",     r"(CREATE TABLE|INSERT INTO)"),
    ("/swagger.json",          "medium",   r'"(openapi|swagger)"'),
    ("/swagger/ui/",           "low",      None),
    ("/api-docs",              "low",      None),
    ("/api/v1",                "info",     None),
    ("/api/v2",                "info",     None),
    ("/graphql",               "low",      r'"(data|errors)"'),
    ("/graphiql",              "medium",   r"<title>.*[Gg]raphi"),
    ("/actuator",              "high",     r'"_links"'),
    ("/actuator/env",          "critical", r"(spring|profiles)"),
    ("/actuator/heapdump",     "critical", None),
    ("/debug/vars",            "high",     r'"(memstats|cmdline)"'),   # pprof Go
    ("/server-status",         "medium",   r"(Apache|Server uptime)"),
    ("/phpinfo.php",           "high",     r"phpinfo\(\)"),
    ("/info.php",              "high",     r"phpinfo\(\)"),
    ("/admin/",                "low",      None),
    ("/administrator/",        "low",      None),
    ("/wp-admin/",             "info",     None),
    ("/wp-login.php",          "info",     None),
    ("/.DS_Store",             "low",      None),
    ("/robots.txt",            "info",     None),
    ("/crossdomain.xml",       "low",      r"<cross-domain-policy>"),
    ("/.svn/entries",          "medium",   r"\d+"),
    ("/web.config",            "medium",   r"<configuration>"),
    ("/composer.lock",         "medium",   r'"packages"'),
    ("/package.json",          "low",      r'"(dependencies|devDependencies)"'),
    ("/.htaccess",             "medium",   r"(RewriteRule|Deny)"),
    ("/cgi-bin/",              "low",      None),
    ("/console/",              "medium",   None),
    ("/jenkins/",              "medium",   None),
    ("/solr/",                 "medium",   None),
    ("/elasticsearch/",        "high",     r'"cluster_name"'),
    ("/_cat/indices",          "high",     None),
]

# Assinaturas de tecnologias: (nome, onde: header|body|cookie, padrão)
TECH_SIGNATURES = [
    ("WordPress",      "body",   r"wp-content|wp-includes"),
    ("Drupal",         "body",   r"Drupal\.settings|drupal"),
    ("Joomla",         "body",   r"Joomla!"),
    ("React",          "body",   r"__NEXT_DATA__|react"),
    ("Next.js",        "body",   r"__NEXT_DATA__"),
    ("Vue.js",         "body",   r"data-v-[0-9a-f]{8}|vue"),
    ("Angular",        "body",   r"ng-version"),
    ("Bootstrap",      "body",   r"bootstrap(\.min)?\.(css|js)"),
    ("jQuery",         "body",   r"jquery(-[0-9.]+)?(\.min)?\.js"),
    ("PHP",            "header", r"PHP[/ ]?([\d.]+)?"),
    ("Laravel",        "cookie", r"laravel_session|XSRF-TOKEN"),
    ("ASP.NET",        "header", r"ASP\.NET|X-AspNet-Version"),
    ("Java/JSP",       "header", r"JSESSIONID"),
    ("Django",         "cookie", r"csrfid|sessionid"),
    ("Rails",          "cookie", r"_session_id"),
    ("Express/Node",   "header", r"Express|X-Powered-By: Node"),
    ("Nginx",          "header", r"nginx[/ ]?([\d.]+)?"),
    ("Apache",         "header", r"Apache[/ ]?([\d.]+)?"),
    ("IIS",            "header", r"IIS|Microsoft-IIS"),
    ("LiteSpeed",      "header", r"LiteSpeed"),
    ("Cloudflare",     "header", r"cloudflare"),
    ("AWS S3",         "header", r"x-amz|awselb|AmazonS3"),
    ("AWS ELB",        "header", r"awswaf|awselb"),
    ("CloudFront",     "header", r"cloudfront"),
    ("Akamai",         "header", r"akamai"),
    ("GCP",            "header", r"x-goog|gcp|Google Frontend"),
    ("Azure",          "header", r"x-azure|x-arr-server"),
    ("Vercel",         "header", r"x-vercel"),
    ("Shopify",        "header", r"shopify|x-shopid"),
]

# Security headers: (nome, severidade da ausência)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "medium"),
    ("Content-Security-Policy",   "high"),
    ("X-Content-Type-Options",    "low"),
    ("X-Frame-Options",           "medium"),
    ("Referrer-Policy",           "low"),
]


def _log(tag, msg):
    print(f"[WEB:{tag}] {msg}")


def _random_ua():
    return random.choice(USER_AGENTS)


def _rand_path():
    """Rota inexistente para calibrar o 'soft-404'."""
    return f"/{random.randint(10**8, 10**9 - 1)}x{random.randint(100,999)}"


# ============================================================
# MOTOR HTTP COMPARTILHADO (com jitter anti-fingerprint)
# ============================================================

async def http_get(session, url, semaphore):
    """GET com semáforo, retry/backoff, jitter e LOG do erro real."""
    async with semaphore:
        await asyncio.sleep(random.uniform(*DELAY_JITTER))
        last_err = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                    allow_redirects=True,
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, dict(resp.headers), body
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_err = f"{type(e).__name__}: {e}"
                if attempt == MAX_RETRIES:
                    _log("NET", f"FALHA em {url} -> {last_err}")
                    return None, None, None
                await asyncio.sleep(2 ** attempt)
    return None, None, None


# ============================================================
# FINGERPRINTING
# ============================================================
def fingerprint_from_response(status, headers, body):
    """Extrai tecnologias, servidor e security headers ausentes."""
    techs = set()
    server = headers.get("Server", "unknown") if headers else "unknown"

    lowered_headers = {k.lower(): v for k, v in (headers or {}).items()}
    header_blob = " ".join(str(v) for v in lowered_headers.values())
    cookie_blob = lowered_headers.get("set-cookie", "")

    for name, where, pattern in TECH_SIGNATURES:
        try:
            if where == "header" and re.search(pattern, header_blob, re.I):
                techs.add(name)
            elif where == "body" and body and re.search(pattern, body[:50000], re.I):
                techs.add(name)
            elif where == "cookie" and re.search(pattern, cookie_blob, re.I):
                techs.add(name)
        except re.error:
            continue

    missing_security = [
        h for h, sev in SECURITY_HEADERS
        if h.lower() not in lowered_headers
    ]

    return {
        "server": server,
        "technologies": sorted(techs),
        "missing_security_headers": missing_security,
        "http_status": status,
    }


# ============================================================
# DESCOBERTA DE ENDPOINTS SENSÍVEIS
# ============================================================
async def probe_endpoint(session, base_url, path, severity, confirm_pattern,
                        semaphore, soft404_sizes):
    """Testa um endpoint e valida com status + conteúdo (anti soft-404)."""
    url = f"{base_url}{path}"
    status, headers, body = await http_get(session, url, semaphore)
    if status is None:
        return None

    # Filtro soft-404: resposta idêntica ao 404 customizado = falso positivo
    if len(body or "") in soft404_sizes:
        return None

    # Regra 1: 401/403 significa que o endpoint EXISTE mas é protegido (ainda útil!)
    if status in (401, 403):
        return {
            "path": path, "status": status, "severity": "info",
            "note": "Endpoint existe (protegido por autenticação/WAF)", "url": url,
        }

    # Regra 2: 200 exige confirmação de conteúdo quando temos padrão conhecido
    if status == 200:
        if confirm_pattern:
            if re.search(confirm_pattern, body or "", re.I):
                return {
                    "path": path, "status": status, "severity": severity,
                    "note": "Conteúdo sensível confirmado via assinatura", "url": url,
                }
            return None  # 200 mas sem o conteúdo esperado = página de erro customizada
        return {
            "path": path, "status": status, "severity": severity,
            "note": "Acessível (verificação manual recomendada)", "url": url,
        }

    return None


async def analyze_host(base_url):

    """
    Análise completa de um host HTTP:
    1. Fingerprint do index
    1.5 Mini-crawler: extrai arquivos .js do HTML (para o cloud_recon)
    2. Calibração soft-404
    3. Prova todos os endpoints sensíveis
    Retorna dict para consolidação no JSON do relatório.
    """
    base_url = base_url.rstrip("/")
    semaphore = asyncio.Semaphore(HTTP_CONCURRENCY)

    connector = aiohttp.TCPConnector(limit=HTTP_CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(
        headers={"User-Agent": _random_ua()}, connector=connector
    ) as session:

        # --- 1. Fingerprinting da página principal
        status, headers, body = await http_get(session, base_url, semaphore)
        if status is None:
            _log("HOST", f"{base_url}: inacessível (HTTP down ou bloqueado).")
            return None

        fp = fingerprint_from_response(status, headers, body)
        _log("HOST", f"{base_url}: {fp['server']} | Tech: {', '.join(fp['technologies']) or 'n/d'}")

        # --- 1.5 Mini-crawler: extrai arquivos .js do HTML para o cloud_recon
        js_urls = []
        if body:
            for m in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body[:100000], re.I):
                if m.startswith("http"):
                    js_urls.append(m)
                elif m.startswith("/"):
                    js_urls.append(f"{base_url}{m}")
                else:
                    js_urls.append(f"{base_url}/{m}")
        js_urls = list(set(js_urls))[:15]
        if js_urls:
            _log("CRAWL", f"{len(js_urls)} arquivos .js detectados no HTML")

        # --- 2. Calibração soft-404 (tamanhos da página 404 em 3 rotas fake)
        soft404_sizes = set()
        for _ in range(3):
            s, _, b = await http_get(session, f"{base_url}{_rand_path()}", semaphore)
            if s in (200, 404) and b is not None:
                soft404_sizes.add(len(b))
        _log("CALIB", f"Soft-404 calibrado com tamanhos: {soft404_sizes}")

        # --- 3. Endpoints sensíveis em paralelo (limitado pelo semaphore)
        tasks = [
            probe_endpoint(session, base_url, path, sev, pattern, semaphore, soft404_sizes)
            for path, sev, pattern in SENSITIVE_ENDPOINTS
        ]
        found = [r for r in await asyncio.gather(*tasks) if r is not None]

    for f in found:
        _log("FIND", f"[{f['severity'].upper()}] {base_url}{f['path']} -> HTTP {f['status']}")

    return {
        "module": "websearch",
        "url": base_url,
        "timestamp": datetime.now().isoformat(),
        "fingerprint": fp,
        "js_assets": js_urls,
        "sensitive_endpoints": found,
        "endpoints_tested": len(SENSITIVE_ENDPOINTS),


     }


def analyze_host_sync(base_url):
    """Wrapper síncrono para integração em pipeline v1.1."""
    return asyncio.run(analyze_host(base_url))


if __name__ == "__main__":
    import sys, json
    target = sys.argv[1] if len(sys.argv) > 1 else "http://testphp.vulnweb.com"
    result = asyncio.run(analyze_host(target))
    print(json.dumps(result, indent=2, ensure_ascii=False))
