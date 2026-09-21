"""
CyShield Engine v2.0 - diff_engine.py
Monitoramento contínuo: compara o scan atual com o último scan salvo
do mesmo domínio e gera um diff estruturado para o relatório.
"""
import re
import json
import glob
import os
from datetime import datetime


def _log(tag, msg):
    print(f"[DIFF:{tag}] {msg}")

import re

def find_previous_report(domain, current_timestamp_iso):
    pattern = f"reports/{domain}_*.json"
    # Extrai os 15 últimos chars (YYYYmmdd_HHMMSS) de forma robusta
    ts_re = re.compile(r"(\d{8}_\d{6})\.json$")
    candidates = []
    current_dt = datetime.fromisoformat(current_timestamp_iso)
    for path in glob.glob(pattern):
        m = ts_re.search(os.path.basename(path))
        if not m:
            continue
        try:
            file_dt = datetime.strptime(m.group(1), "%Y%m%d_%H%M%S")
        except ValueError:
            continue
        if file_dt < current_dt:
            candidates.append((file_dt, path))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


def load_report(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        _log("LOAD", f"Erro ao ler {path}: {e}")
        return None


def diff_scan(current, previous):
    """
    Compara dois relatórios v2 e retorna o diff estruturado.
    """
    prev_actives = (previous or {}).get("actives", {}) or {}
    curr_actives = (current or {}).get("actives", {}) or {}

    new_subs = sorted(set(curr_actives) - set(prev_actives))
    removed_subs = sorted(set(prev_actives) - set(curr_actives))
    common = set(prev_actives) & set(curr_actives)

    # --- Novas portas por host
    new_ports = {}
    for sub in common:
        prev_p = set(prev_actives[sub].get("open_ports", []))
        curr_p = set(curr_actives[sub].get("open_ports", []))
        added = sorted(curr_p - prev_p)
        if added:
            new_ports[sub] = added

    # --- Endpoints sensíveis: novos e resolvidos (remediados)
    def _endpoint_map(active_data):
        web = active_data.get("web_intel") or {}
        return {ep["path"]: ep.get("severity", "info")
                for ep in web.get("sensitive_endpoints", [])}

    new_endpoints, resolved_endpoints = {}, {}
    for sub in common:
        prev_eps = _endpoint_map(prev_actives[sub])
        curr_eps = _endpoint_map(curr_actives[sub])
        added = {p: s for p, s in curr_eps.items() if p not in prev_eps}
        removed = {p: s for p, s in prev_eps.items() if p not in curr_eps}
        if added:
            new_endpoints[sub] = added
        if removed:
            resolved_endpoints[sub] = removed

    # --- Cloud: novos buckets expostos
    prev_cloud = ((previous or {}).get("cloud_recon") or {}).get("buckets_analyzed", []) or []
    curr_cloud = ((current or {}).get("cloud_recon") or {}).get("buckets_analyzed", []) or []
    prev_b = {f"{c['provider']}:{c['bucket']}" for c in prev_cloud
              if c.get("severity") in ("high", "critical")}
    curr_b = {f"{c['provider']}:{c['bucket']}" for c in curr_cloud
              if c.get("severity") in ("high", "critical")}

    diff = {
        "compared_against": (previous or {}).get("timestamp", "desconhecido"),
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "new_open_ports": new_ports,
        "new_sensitive_endpoints": new_endpoints,
        "resolved_sensitive_endpoints": resolved_endpoints,
        "new_exposed_buckets": sorted(curr_b - prev_b),
        "has_changes": bool(new_subs or removed_subs or new_ports
                            or new_endpoints or resolved_endpoints
                            or (curr_b - prev_b)),
    }
    return diff


def attach_diff_if_available(general_report):
    """
    Ponto de integração no cyshield_core.py: chame logo após montar o
    general_report['summary']. Modifica o report in-place e retorna o diff.
    """
    prev_path = find_previous_report(
        general_report["domain"], general_report["timestamp"])
    if not prev_path:
        _log("INFO", "Primeiro scan deste domínio — sem baseline para diff.")
        general_report["diff_vs_previous"] = None
        return None

    previous = load_report(prev_path)
    if not previous:
        general_report["diff_vs_previous"] = None
        return None

    diff = diff_scan(general_report, previous)
    general_report["diff_vs_previous"] = diff
    _log("DONE", f"Comparado com scan de {diff['compared_against'][:19]}. "
                 f"Mudanças: {'SIM' if diff['has_changes'] else 'NENHUMA'}")
    return diff
