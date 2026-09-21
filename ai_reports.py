import os
import json
import markdown
from anthropic import Anthropic
from weasyprint import HTML, CSS

def convert_md_to_pdf(md_content, pdf_path):
    """Converte texto Markdown em um PDF estilizado."""
    try:
        # Converter Markdown para HTML
        html_body = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])

        # Estilização CSS para o PDF (Layout Profissional Dark/Clean)
        custom_css = CSS(string='''
            @page {
                size: A4;
                margin: 20mm;
            }
            body {
                font-family: Arial, sans-serif;
                color: #24292e;
                line-height: 1.6;
                font-size: 11pt;
            }
            h1, h2, h3 {
                color: #0366d6;
                border-bottom: 1px solid #eaecef;
                padding-bottom: 0.3em;
            }
            code {
                background-color: #f6f8fa;
                padding: 2px 4px;
                border-radius: 3px;
                font-family: monospace;
            }
            pre {
                background-color: #f6f8fa;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            th, td {
                border: 1px solid #dfe2e5;
                padding: 6px 13px;
            }
            th {
                background-color: #f6f8fa;
            }
            blockquote {
                color: #6a737d;
                border-left: 0.25em solid #dfe2e5;
                padding: 0 1em;
                margin: 0;
            }
        ''')

        # Gerar o PDF a partir do HTML
        HTML(string=f"<html><body>{html_body}</body></html>").write_pdf(pdf_path, stylesheets=[custom_css])
        print(f"[+] Relatório executivo em PDF gerado: {pdf_path}")
        return True
    except Exception as e:
        print(f"[!] Erro ao converter relatório para PDF: {e}")
        return False

def generate_ai_report(scan_data, api_key):
    """Envia dados do scan para o Claude e gera relatórios em Markdown e PDF."""
    if not api_key:
        print("[!] Erro: Chave da API Anthropic não fornecida.")
        return None

    print("\n[*] Conectando à API da Anthropic (Claude) para análise de risco...")

    client = Anthropic(api_key=api_key)

    system_prompt = (
       "Você é um CISO e Especialista Sênior em Cibersegurança e Red Team."
        " Analise os dados brutos de scan (estrutura Enterprise v2: ativos com"
        " ports/vulns/web_intel/fingerprint, endpoints sensíveis, cloud buckets"
        " e JS intelligence) e gere relatório executivo em Markdown contendo:"
        " 1. Resumo Executivo para C-Level; 2. Matriz de Severidade (inclua"
        " achados de cloud como anonymous_write=CRÍTICO e chaves AKIA/AIza em JS"
        " =CRÍTICO); 3. Análise de Impacto no Negócio por ativo; 4. Plano de"
        " Remediação priorizado com esforço estimado (S/M/L);"
        " 5. Seção 'Superfície de Ataque Descoberta' resumindo a metodologia"
        " passiva/ativa/permutações usada."
        " Se existir a chave 'diff_vs_previous' com mudanças, destaque-as numa seção"
        " 'MUDANÇAS DESDE O ÚLTIMO SCAN' priorizando novos subdomínios, portas e"
        " endpoints expostos; se diff for None, mencione que é o scan baseline."
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=4000,
            system=system_prompt,
            messages=[{
                "role": "user",
                "content": f"Análise os seguintes dados de varredura: {json.dumps(scan_data, indent=2)}"
            }]
        )

        report_md = ""
        for block in response.content:
            if getattr(block, "type", None) == "text":
                report_md += block.text

        if not report_md:
            print("[!] Erro: Nenhum texto retornado pelo modelo.")
            return None

        print("[+] Análise de Inteligência concluída com sucesso!")
        return report_md

    except Exception as e:
        print(f"[!] Erro ao chamar a API da Anthropic: {e}")
        return None
