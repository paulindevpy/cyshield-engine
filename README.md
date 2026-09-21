# 🛡️ CyShield Engine v2.0 Enterprise

> **Asynchronous Security Reconnaissance & Vulnerability Assessment Platform**  
> Motor de auditoria de segurança assíncrono e contínuo para ecossistemas web e infraestrutura em nuvem.

---

## 🏗️ Arquitetura do Sistema

```mermaid
flowchart TD
    A[config.yaml] --> B[cyshield_core.py - Async Core Engine]
    C[Targets Input / -t] --> B
    
    subgraph Engine Pipeline
        B --> D[recon.py - Passive/Active DNS]
        B --> E[portscan.py & vulnscan.py]
        B --> F[websearch.py - Tech Fingerprint]
        B --> G[cloud_recon.py - Buckets S3/GCS/Azure]
        B --> H[diff_engine.py - Historical Comparison]
    end
    
    B --> I[storage.py - SQLite3 WAL Mode]
    B --> J[reports/*.json & *.pdf]
    
    I --> K[(cyshield.db)]
    
    subgraph Exposição & Servidor
        K --> L[dashboard.py - FastAPI REST Server]
        L --> M[Frontend SaaS / Swagger UI]
    end
