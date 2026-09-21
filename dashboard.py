from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json
import glob
import os
import re
from typing import List, Dict, Any, Optional

LOG_TAG = "[API:DASHBOARD]"
REPORTS_DIR = "reports"

app = FastAPI(
    title="CyShield Engine API",
    description="API para visualização e acompanhamento de auditorias de segurança",
    version="2.0-enterprise",
)

# Habilita CORS para permitir que frontends locais/web se conectem à API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _extract_timestamp(filename: str) -> str:
    """Extrai o timestamp (YYYYMMDD_HHMMSS) do nome do arquivo com regex."""
    match = re.search(r"(\d{8}_\d{6})\.json$", filename)
    return match.group(1) if match else ""


def _get_all_report_files(domain: Optional[str] = None) -> List[str]:
    """Busca arquivos .json na pasta reports/ ordenados do mais recente para o mais antigo."""
    if not os.path.exists(REPORTS_DIR):
        return []

    pattern = f"{REPORTS_DIR}/{domain}_*.json" if domain else f"{REPORTS_DIR}/*.json"
    files = glob.glob(pattern)

    # Ordena pelo timestamp decrescente (mais recentes primeiro)
    files.sort(key=_extract_timestamp, reverse=True)
    return files


@app.get("/", tags=["Health"])
def health_check() -> Dict[str, str]:
    """Endpoint de verificação de status da API."""
    return {"status": "online", "engine": "CyShield Engine v2.0 Enterprise"}


@app.get("/scans", tags=["Scans"])
def list_scans() -> List[Dict[str, Any]]:
    """Lista todos os scans salvos na pasta reports/ com resumo de dados."""
    files = _get_all_report_files()
    scans_summary = []

    for file_path in files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            scans_summary.append({
                "domain": data.get("domain"),
                "timestamp": data.get("timestamp"),
                "filename": os.path.basename(file_path),
                "hosts_scanned": data.get("summary", {}).get("hosts_scanned", 0),
                "critical": data.get("summary", {}).get("critical", 0),
                "high": data.get("summary", {}).get("high", 0),
                "scan_duration_seconds": data.get("summary", {}).get("scan_duration_seconds", 0),
                "has_diff": data.get("diff_vs_previous") is not None
            })
        except Exception as e:
            print(f"{LOG_TAG} Erro ao ler arquivo {file_path}: {type(e).__name__} - {e}")
            continue

    return scans_summary


@app.get("/scans/{domain}", tags=["Scans"])
def get_latest_scan_by_domain(domain: str) -> Dict[str, Any]:
    """Retorna o JSON bruto do scan mais recente para o domínio especificado."""
    files = _get_all_report_files(domain)

    if not files:
        raise HTTPException(
            status_code=404,
            detail=f"Nenhum relatório encontrado para o domínio '{domain}'."
        )

    latest_file = files[0]
    try:
        with open(latest_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao ler relatório: {type(e).__name__} - {e}"
        )


@app.get("/diff/{domain}", tags=["Scans"])
def get_latest_diff(domain: str) -> Dict[str, Any]:
    """Retorna os dados do diff do último scan em comparação com o scan anterior."""
    scan_data = get_latest_scan_by_domain(domain)
    diff_data = scan_data.get("diff_vs_previous")

    if not diff_data:
        return {
            "domain": domain,
            "has_diff": False,
            "message": "Nenhum histórico anterior para comparação ou sem alterações registradas."
        }

    return {
        "domain": domain,
        "has_diff": True,
        "diff": diff_data
    }


if __name__ == "__main__":
    import uvicorn
    print(f"{LOG_TAG} Iniciando servidor da Dashboard API na porta 8000...")
    uvicorn.run("dashboard:app", host="0.0.0.0", port=8000, reload=True)
