# 🛡️ CyShield Engine v2.0 Enterprise

> **Asynchronous Attack Surface Management & Vulnerability Assessment Platform**  
> Motor de auditoria de segurança assíncrono e contínuo para ecossistemas web e infraestrutura em nuvem.

---

## 📌 Visão Geral

O **CyShield Engine v2.0 Enterprise** é um orquestrador assíncrono desenvolvido em **Python 3 (`asyncio`)** projetado para auditorias de segurança autorizadas, programas de Bug Bounty e equipes de SecOps/AppSec. 

A plataforma foi arquitetada do zero com foco em **baixo consumo de recursos, zero latência de I/O e facilidade de implantação em nuvem para SaaS**.

---


🚀 Módulos & FuncionalidadesMóduloComponenteDescrição Técnico-Operacionalcyshield_core.pyOrquestradorGerencia o pipeline assíncrono, isolamento de falhas por host e controle de concorrência via asyncio.Semaphore.config_loader.pyConfiguraçãoValidação defensiva de schema YAML para limites de concorrência, timeouts e fallbacks automáticos.recon.pyReconhecimentoConsulta Certificate Transparency (crt.sh), HackerTarget, brute-force concorrente e filtro de Wildcard DNS.portscan.pyScannerTCP Connect Scan assíncrono de alta performance sobre portas críticas via sockets asyncio.vulnscan.pyScannerIntegração em segundo plano via subprocess com a ferramenta Nuclei (-jsonl) sem arquivos temporários em disco.websearch.pyWebIntelFingerprinting de tecnologias web, busca de arquivos .js e filtro de falsos positivos com calibração Soft-404.cloud_recon.pyCloud ReconEnumeração de buckets (S3, GCS, Azure) e regex parser para extração de segredos e chaves de API expostas em JS.diff_engine.pyInteligênciaAlgoritmo de comparação temporal para identificar novas portas abertas, subdomínios criados ou falhas corrigidas.storage.pyPersistênciaBanco de dados SQLite3 em modo WAL (Write-Ahead Logging) isolado em run_in_executor para evitar travamentos de I/O.dashboard.pyAPI RESTMicroserviço em FastAPI para consultar relatórios e fornecer dados estruturados para interfaces Web.⚙️ Instalação e ExecuçãoPré-requisitosPython 3.10+ProjectDiscovery Nuclei instalado no PATH do sistema.1. Clonar o repositório e instalar dependênciasBashgit clone [https://github.com/paulindevpy/cyshield-engine.git](https://github.com/paulindevpy/cyshield-engine.git)
cd cyshield-engine
pip install -r requirements.txt
2. Configuração dos Limites (config.yaml)YAMLconcurrency:
  max_hosts: 5
  max_dns_threads: 50
timeouts:
  http_seconds: 10
  nuclei_seconds: 600
3. Executar o ScannerBash# Varredura simples em um alvo
python3 cyshield_core.py -t scanme.nmap.org

# Varredura com relatório executivo gerado por IA (Claude)
ANTHROPIC_API_KEY="sk-ant-..." python3 cyshield_core.py -t scanme.nmap.org --ai
4. Iniciar a API REST (Dashboard)Bashpython3 dashboard.py
Acesse a documentação Swagger interativa em: http://127.0.0.1:8000/docs🐳 Implantação com DockerA infraestrutura está 100% pronta para rodar em servidores na nuvem ou VPS:Bash# Subir o ambiente completo
docker-compose up -d --build

# Executar scan isolado no container
docker-compose run --rm cyshield-scanner -t scanme.nmap.org
📊 Formato das Saídas (reports/)Os relatórios são salvos em JSON com metadados estruturados para integração:JSON{
  "engine": "CyShield Engine",
  "version": "2.0-enterprise",
  "domain": "scanme.nmap.org",
  "timestamp": "2026-09-21T20:17:18",
  "summary": {
    "scan_duration_seconds": 178.6,
    "hosts_scanned": 1,
    "critical": 0,
    "high": 1
  },
  "diff_vs_previous": {
    "has_changes": false,
    "compared_against": "20260921_193953"
  }
}
⚠️ Aviso Legal / DisclaimerEsta ferramenta foi desenvolvida exclusivamente para fins educacionais, auditorias de segurança autorizadas e programas de Bug Bounty com escopo formalizado. O uso não autorizado contra infraestruturas de terceiros é ilegal. O desenvolvedor não se responsabiliza pelo uso indevido da plataforma.


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
