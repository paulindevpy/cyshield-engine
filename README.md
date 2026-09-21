# 🛡️ CyShield Engine v2.0 Enterprise

> **Asynchronous Attack Surface Management & Vulnerability Assessment Platform**  
> Motor de auditoria de segurança assíncrono e contínuo para ecossistemas web e infraestrutura em nuvem.

---

## 📌 Visão Geral

O **CyShield Engine v2.0 Enterprise** é um orquestrador assíncrono desenvolvido em **Python 3 (`asyncio`)** projetado para auditorias de segurança autorizadas, programas de Bug Bounty e equipes de SecOps/AppSec.

A plataforma foi arquitetada do zero com foco em **baixo consumo de recursos, zero latência de I/O e facilidade de implantação em nuvem para SaaS**.

---

## 🚀 Módulos & Funcionalidades

| Módulo | Componente | Descrição Técnico-Operacional |
| :--- | :---: | :--- |
| **`cyshield_core.py`** | `Orquestrador` | Gerencia o pipeline assíncrono, isolamento de falhas por host e controle de concorrência via `asyncio.Semaphore`. |
| **`config_loader.py`** | `Configuração` | Validação defensiva de schema YAML para limites de concorrência, timeouts e fallbacks automáticos. |
| **`recon.py`** | `Reconhecimento` | Consulta Certificate Transparency (`crt.sh`), HackerTarget, brute-force concorrente e filtro de **Wildcard DNS**. |
| **`portscan.py`** | `Scanner` | TCP Connect Scan assíncrono de alta performance sobre portas críticas via sockets `asyncio`. |
| **`vulnscan.py`** | `Scanner` | Integração em segundo plano via `subprocess` com a ferramenta **Nuclei** (`-jsonl`) sem arquivos temporários em disco. |
| **`websearch.py`** | `WebIntel` | Fingerprinting de tecnologias web, busca de arquivos `.js` e filtro de falsos positivos com calibração **Soft-404**. |
| **`cloud_recon.py`** | `Cloud Recon` | Enumeração de buckets (S3, GCS, Azure) e regex parser para extração de segredos e chaves de API expostas em JS. |
| **`diff_engine.py`** | `Inteligência` | Algoritmo de comparação temporal para identificar novas portas abertas, subdomínios criados ou falhas corrigidas. |
| **`storage.py`** | `Persistência` | Banco de dados SQLite3 em modo **WAL (Write-Ahead Logging)** isolado em `run_in_executor` para evitar travamentos de I/O. |
| **`dashboard.py`** | `API REST` | Microserviço em **FastAPI** para consultar relatórios e fornecer dados estruturados para interfaces Web. |


## ⚙️ Instalação e Execução

### Pré-requisitos
- Python 3.10+
- [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) instalado no PATH do sistema.

### 1. Clonar o repositório e instalar dependências
```bash
git clone [https://github.com/paulindevpy/cyshield-engine.git](https://github.com/paulindevpy/cyshield-engine.git)
cd cyshield-engine
pip install -r requirements.txt


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
