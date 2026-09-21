import asyncio
import json
import os
import sqlite3
from typing import Any, Dict, Optional

LOG_TAG = "[STORAGE:DB]"
DB_PATH = "cyshield.db"


def print_log(msg: str) -> None:
    """Padronização de logs do sistema."""
    print(f"{LOG_TAG} {msg}")


def init_db(db_path: str = DB_PATH) -> None:
    """Inicializa as tabelas do SQLite e ativa o modo WAL para concorrência."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # WAL mode: permite leituras e escritas concorrentes sem travar
        cursor.execute("PRAGMA journal_mode=WAL;")

        # Tabela de Scans (cabeçalho do relatório)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                scan_duration_seconds REAL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                summary_json TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_domain_ts ON scans (domain, timestamp DESC);"
        )

        # Tabela de Findings (vulnerabilidades e achados granulares)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                finding_type TEXT NOT NULL, -- 'vulnerability', 'sensitive_endpoint', 'exposed_bucket'
                severity TEXT NOT NULL,     -- 'critical', 'high', 'medium', 'low', 'info'
                title TEXT NOT NULL,
                details_json TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
            );
        """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);"
        )

        conn.commit()
        conn.close()
        print_log(f"Banco de dados '{db_path}' inicializado com sucesso.")
    except Exception as e:
        print_log(f"Erro ao inicializar o banco: {type(e).__name__} - {e}")
        raise


def _save_scan_sync(report_dict: Dict[str, Any], db_path: str) -> int:
    """Operação bloqueante de escrita no SQLite (roda em thread isolada)."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        domain = report_dict.get("domain", "unknown")
        timestamp = report_dict.get("timestamp", "")
        summary = report_dict.get("summary", {})

        scan_duration = summary.get("scan_duration_seconds", 0.0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)

        # Inserção do scan principal
        cursor.execute(
            """
            INSERT INTO scans (domain, timestamp, scan_duration_seconds, critical_count, high_count, summary_json)
            VALUES (?, ?, ?, ?, ?, ?);
        """,
            (
                domain,
                timestamp,
                scan_duration,
                critical,
                high,
                json.dumps(report_dict, ensure_ascii=False),
            ),
        )

        scan_id = cursor.lastrowid

        # Gravação dos achados (findings) por host
        actives = report_dict.get("actives", {})
        for host, host_data in actives.items():
            # 1. Vulnerabilidades (Nuclei)
            for vuln in host_data.get("vulnerabilities", []):
                info = vuln.get("info", {})
                if isinstance(info, list) and info:
                    info = info[0]
                sev = info.get("severity", "info") if isinstance(info, dict) else "info"
                name = info.get("name", vuln.get("template-id", "Unknown Vuln")) if isinstance(info, dict) else vuln.get("template-id", "Unknown Vuln")

                cursor.execute(
                    """
                    INSERT INTO findings (scan_id, host, finding_type, severity, title, details_json)
                    VALUES (?, ?, ?, ?, ?, ?);
                """,
                    (
                        scan_id,
                        host,
                        "vulnerability",
                        sev,
                        name,
                        json.dumps(vuln, ensure_ascii=False),
                    ),
                )

            # 2. Endpoints Sensíveis
            web_intel = host_data.get("web_intel") or {}
            for ep in web_intel.get("sensitive_endpoints", []):
                cursor.execute(
                    """
                    INSERT INTO findings (scan_id, host, finding_type, severity, title, details_json)
                    VALUES (?, ?, ?, ?, ?, ?);
                """,
                    (
                        scan_id,
                        host,
                        "sensitive_endpoint",
                        ep.get("severity", "info"),
                        f"Endpoint: {ep.get('path')}",
                        json.dumps(ep, ensure_ascii=False),
                    ),
                )

        # 3. Buckets Expostos
        cloud = report_dict.get("cloud_recon") or {}
        for bucket in cloud.get("buckets_analyzed", []):
            if bucket.get("severity") in ["high", "critical", "medium"]:
                cursor.execute(
                    """
                    INSERT INTO findings (scan_id, host, finding_type, severity, title, details_json)
                    VALUES (?, ?, ?, ?, ?, ?);
                """,
                    (
                        scan_id,
                        domain,
                        "exposed_bucket",
                        bucket.get("severity", "medium"),
                        f"Bucket: {bucket.get('bucket')}",
                        json.dumps(bucket, ensure_ascii=False),
                    ),
                )

        conn.commit()
        print_log(f"Scan para '{domain}' [ID: {scan_id}] salvo no banco SQLite.")
        return scan_id

    except Exception as e:
        conn.rollback()
        print_log(f"Erro ao salvar scan no SQLite: {type(e).__name__} - {e}")
        raise
    finally:
        conn.close()


def _get_previous_scan_sync(
    domain: str, db_path: str
) -> Optional[Dict[str, Any]]:
    """Busca o relatório anterior do domínio no banco de dados."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT summary_json FROM scans 
            WHERE domain = ? 
            ORDER BY timestamp DESC 
            LIMIT 1;
        """,
            (domain,),
        )

        row = cursor.fetchone()
        if row:
            return json.loads(row[0])
        return None
    except Exception as e:
        print_log(f"Erro ao consultar scan anterior: {type(e).__name__} - {e}")
        return None
    finally:
        conn.close()


# Wrappers Assíncronos para chamada no cyshield_core.py


async def save_scan(
    report_dict: Dict[str, Any], db_path: str = DB_PATH
) -> int:
    """Interface async para salvar o scan no SQLite sem travar o loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _save_scan_sync, report_dict, db_path
    )


async def get_previous_scan(
    domain: str, db_path: str = DB_PATH
) -> Optional[Dict[str, Any]]:
    """Interface async para buscar o último scan para comparação do Diff Engine."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _get_previous_scan_sync, domain, db_path
    )


if __name__ == "__main__":
    init_db()
    print_log("Módulo storage.py testado localmente com sucesso.")
