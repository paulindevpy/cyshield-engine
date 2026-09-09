<div align="center">

# 🛡️ CyShield Engine v1.0 - Paullo Eduardo

**Next-Gen Asynchronous Cybersecurity Reconnaissance & AI Vulnerability Assessment Pipeline**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active--v1.0-emerald.svg)]()
[![AI Powered](https://img.shields.io/badge/AI-Anthropic%20Claude-purple.svg)](https://www.anthropic.com/)

---

</div>

## 📌 Sobre o Projeto

O **CyShield Engine** é um motor assíncrono modular desenvolvido em Python projetado para automação avançada de segurança cibernética, reconhecimento de superfície de ataque (**Recon**) e análise executiva de riscos impulsionada por Inteligência Artificial (**Anthropic Claude API**).

Projetado para profissionais de **Red Team**, analistas de **AppSec** e **Consultores de Cibersegurança**, a ferramenta automatiza a descoberta de infraestrutura, varredura de portas TCP, validação de vulnerabilidades conhecidas (CVEs via Nuclei) e compila relatórios estratégicos para o nível executivo (*C-Level*).

---

## ⚡ Principais Funcionalidades

- **🔍 Recon Mapeado:** Identificação e enumeração ativa e passiva de subdomínios.
- **⚡ Fast Async PortScan:** Varredura rápida de portas TCP/UDP aproveitando concorrência nativa com `asyncio`.
- **🛡️ Nuclei Scan Integration:** Execução de templates do Nuclei para identificação precisa de CVEs e misconfigurations.
- **🤖 Executive Risk AI Report:** Análise inteligente de risco via **Claude API** que converte dados brutos (JSON) em relatórios executivos em Markdown (`.md`).
- **🔒 Security First:** Gestão segura de segredos e credenciais via variáveis de ambiente (`os.getenv`).

---

## 🏗️ Arquitetura do Sistema

```text
               ┌──────────────────────────────────────────────┐
               │         CyShield Core CLI Engine             │
               │         (cyshield_core.py)                   │
               └──────────────────────┬───────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│    recon.py      │        │   portscan.py    │        │   vulnscan.py    │
│  (Subdomains)    │        │ (Async PortScan) │        │ (Nuclei Engine)  │
└────────┬─────────┘        └────────┬─────────┘        └────────┬─────────┘
         │                           │                           │
         └───────────────────────────┴───────────────────────────┘
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │    Relatório JSON Bruto     │
                      └──────────────┬──────────────┘
                                     │ (Flag --ai)
                                     ▼
                      ┌─────────────────────────────┐
                      │       ai_reports.py         │
                      │  (API Anthropic Claude)     │
                      └──────────────┬──────────────┘
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │   Relatório Executivo .md   │
                      └─────────────────────────────┘
