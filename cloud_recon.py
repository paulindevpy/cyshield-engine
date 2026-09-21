"""
CyShield Engine v2.0 - cloud_recon.py
Cloud storage exposure & JS intelligence:
- AWS S3 / GCS / Azure Blob enumeration + permission check (read/write)
- JavaScript parsing: API endpoints, hardcoded keys, cloud URLs
- Reusa padrões de recon.py/websearch.py: semaphore, retry, UA rotation
"""

import asyncio
import re
import random
import string
from datetime import datetime
from urllib.parse import urlparse

import aiohttp

# ============================================================
# CONFIG
# ============================================================
HTTP_CONCURRENCY = 10
REQUEST_TIMEOUT = 12
MAX_RETRIES = 2
PROBE_FILE_CONTENT = b"cyshield-engine-authorization-test-file"

# Sufixos/prefixos para derivar nomes de bucket a partir do domínio
BUCKET_WORDS = [
    "", "backup", "backups", "bak", "assets", "static", "media", "files",
    "data", "uploads", "img", "images", "storage", "prod", "production",
    "dev", "staging", "test", "old", "archive", "logs", "export", "tmp",
    "download", "downloads", "private", "public", "db", "dump", "release",
]


def _log(tag, msg):
    print(f"[CLOUD:{tag}] {msg}")


def _rand_ua():
    return random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    ])


# ============================================================
# GERAÇÃO DE CANDIDATOS A BUCKET
# ============================================================
def generate_bucket_names(domain, subdomains=None):
    """
    Deriva candidatos a bucket do domínio e subdomínios conhecidos.
    'acme.com' -> acme, acme-backup, backups-acme, acme-prod-assets, acme-com...
    """
    root = domain.split(".")[0].lower().replace("-", "")
    subs = set()
    for sd in (subdomains or []):
        first = sd.split(".")[0]
        if first and len(first) > 2 and first not in ("www",):
            subs.add(first)

    names = set()
    for base in {root} | subs:
        for w in BUCKET_WORDS:
            if w:
                names.update([f"{base}-{w}", f"{w}-{base}", f"{base}{w}"])
            else:
                names.add(base)
    names.discard(root + "-")  # sanitiza lixo
    return sorted(n for n in names if n)


# ============================================================
# VERIFICAÇÃO DE BUCKETS
# ============================================================
async def check_s3_bucket(session, bucket, semaphore):
    url = f"https://{bucket}.s3.amazonaws.com/"
    status, _, body = await _req(session, url, semaphore)
    if status is None or status == 404:
        return None
    # CORREÇÃO: S3 anônimo responde 403 TANTO para "existe negado"
    # QUANTO para "não existe". O XML diz a verdade:
    if "NoSuchBucket" in (body or ""):
        return None
    if status == 200 and body and "<ListBucketResult" in body:
        return [{"provider": "AWS S3", "bucket": bucket, "url": url,
                 "severity": "high", "permission": "public_list",
                 "note": "Listagem pública de objetos habilitada"}]
    # 403 SEM NoSuchBucket = bucket existe, acesso negado (info real)
    if status == 403:
        return [{"provider": "AWS S3", "bucket": bucket, "url": url,
                 "severity": "info", "permission": "exists",
                 "note": "Bucket existe (403 - acesso negado)"}]
    return None


async def check_gcs_bucket(session, bucket, semaphore):
    url = f"https://storage.googleapis.com/{bucket}/"
    status, _, body = await _req(session, url, semaphore)
    if status is None or status in (404, 400):
        return None
    if status == 200 and body and "<ListBucketResult" in body:
        return [{"provider": "GCS", "bucket": bucket, "url": url, "severity": "high",
                 "permission": "public_list", "note": "Listagem pública GCS"}]
    if status == 200:
        return [{"provider": "GCS", "bucket": bucket, "url": url, "severity": "info",
                 "permission": "exists", "note": "Bucket GCS existe"}]
    if status == 403 and "NoSuchBucket" not in (body or ""):
        return [{"provider": "GCS", "bucket": bucket, "url": url, "severity": "info",
                 "permission": "exists", "note": "Bucket GCS existe (403)"}]
    return None

async def check_azure_container(session, bucket, semaphore):
    url = f"https://{bucket}.blob.core.windows.net/?restype=container&comp=list"
    status, _, body = await _req(session, url, semaphore)
    if status == 404 or status is None:
        return None
    if status == 200 and body and "EnumerationResults" in body:
        return [{"provider": "Azure Blob", "bucket": bucket, "url": url, "severity": "high",
                 "permission": "public_list", "note": "Container Azure com listagem pública"}]
    if status == 200:
        return [{"provider": "Azure Blob", "bucket": bucket, "url": url, "severity": "info",
                 "permission": "exists", "note": "Container Azure existe"}]
    return None


async def _req(session, url, semaphore, method="GET", data=None):
    """GET/PUT/DELETE com retry/backoff e semaphore global."""
    async with semaphore:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.request(
                    method, url, data=data,
                    timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                    headers={"User-Agent": _rand_ua()},
                ) as resp:
                    body = await resp.text(errors="ignore")
                    return resp.status, dict(resp.headers), body
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt == MAX_RETRIES:
                    return None, None, None
                await asyncio.sleep(2 ** attempt)
    return None, None, None


async def enumerate_buckets(domain, subdomains=None, max_buckets=120):
    """Executa a triagem de buckets nos 3 provedores em paralelo."""
    candidates = generate_bucket_names(domain, subdomains)[:max_buckets]
    _log("ENUM", f"Testando {len(candidates)} nomes de buckets derivados em 3 provedores...")
    semaphore = asyncio.Semaphore(HTTP_CONCURRENCY)

    connector = aiohttp.TCPConnector(limit=HTTP_CONCURRENCY, ssl=False)
    all_findings = []
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for name in candidates:
            tasks.append(check_s3_bucket(session, name, semaphore))
            tasks.append(check_gcs_bucket(session, name, semaphore))
            tasks.append(check_azure_container(session, name, semaphore))
        results = await asyncio.gather(*tasks)

    for r in results:
        if r:
            all_findings.extend(r)

    criticals = [f for f in all_findings if f["severity"] in ("critical", "high")]
    for f in criticals:
        _log("FIND", f"[{f['severity'].upper()}] {f['provider']}:{f['bucket']} -> {f['permission']}")
    _log("DONE", f"Triagem de cloud concluída: {len(all_findings)} buckets analisados em detalhe.")
    return all_findings


# ============================================================
# PARSING DE JAVASCRIPT (endpoints, chaves, cloud URLs)
# ============================================================
JS_PATTERNS = [
    ("aws_access_key", "critical", r"AKIA[0-9A-Z]{16}"),
    ("google_api_key", "critical", r"AIza[0-9A-Za-z\-_]{35}"),
    ("firebase_url",   "high",     r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("s3_url",         "medium",   r"https://[a-zA-Z0-9\-_]+\.s3[.\-][a-zA-Z0-9\-]*\.?amazonaws\.com"),
    ("gcs_url",        "medium",   r"https://storage\.cloud\.google\.com/[a-zA-Z0-9\-_]+"),
    ("azure_blob",     "medium",   r"https://[a-zA-Z0-9\-_]+\.blob\.core\.windows\.net"),
    ("internal_api",   "info",     r"[\"'](/api/[a-zA-Z0-9/_\-\.]+)[\"']"),
    ("bearer_token",   "critical", r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}"),
    ("private_ip",     "low",      r"https?://(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9\.]+"),
    ("hardcoded_key",  "high",     r"(api[_\-]?key|apikey|secret)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9\-_]{16,}[\"']"),
]


def parse_javascript(js_code, source_url=""):
    """Aplica regexes de inteligência sobre o código JS."""
    findings = []
    for ftype, severity, pattern in JS_PATTERNS:
        for match in set(re.findall(pattern, js_code)):
            value = match if isinstance(match, str) else match[0]
            findings.append({
                "type": ftype, "severity": severity,
                "value": value[:200], "source": source_url,
            })
    return findings


async def harvest_js_intel(urls_js, semaphore=None):
    """
    Baixa arquivos .js de uma lista de URLs e aplica o parser.
    Recebe lista de URLs (do websearch.py ou crawling básico).
    """
    semaphore = semaphore or asyncio.Semaphore(HTTP_CONCURRENCY)
    intel = []
    connector = aiohttp.TCPConnector(limit=HTTP_CONCURRENCY, ssl=False)
    async with aiohttp.ClientSession(
        connector=connector, headers={"User-Agent": _rand_ua()}
    ) as session:
        async def _grab(url):
            _, _, body = await _req(session, url, semaphore)
            if body:
                intel.extend(parse_javascript(body, source_url=url))
        await asyncio.gather(*(_grab(u) for u in urls_js))

    dedup = {tuple(sorted(f.items())): f for f in intel}
    final = list(dedup.values())
    crits = [f for f in final if f["severity"] == "critical"]
    _log("JS", f"Parsing concluído: {len(final)} achados ({len(crits)} críticos) em {len(urls_js)} arquivos.")
    return final


# ============================================================
# ORQUESTRADOR
# ============================================================
async def run_cloud_recon(domain, subdomains=None, js_urls=None):
    """
    Pipeline cloud completo. Retorna dict para consolidação no JSON.
    """
    buckets = await enumerate_buckets(domain, subdomains)
    js_intel = []
    if js_urls:
        js_intel = await harvest_js_intel(js_urls)
    return {
        "module": "cloud_recon",
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "buckets_analyzed": buckets,
        "js_intelligence": js_intel,
        "summary": {
            "buckets_found": len(buckets),
            "critical_findings": len([f for f in buckets + js_intel if f["severity"] == "critical"]),
        },
    }


if __name__ == "__main__":
    import sys, json
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run_cloud_recon(target))
    print(json.dumps(result, indent=2, ensure_ascii=False))
