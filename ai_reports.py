import os
import json
from anthropic import Anthropic

def general_report_executive(dados_scan, api_key):
    """
    Recebe o dicionário/JSON da pipeline e geral uma análise técnica
    e executiva de segurança utilizando a API do Claude.
    """
    print("\n[*] Conectando à API da Anthropic (Claude) para análise de risco...")

    client = Anthropic(api_key=api_key)

    ### PROMPT estruturado para alinhar a postura do modelo como Especialista em Red Team
    prompt_system = """
    Você é um Engenheiro Sênior de Cibersegurança e Líder de Red Team (CyShield Engine).
    Sua missão é analisar os dados brutos de varredura fornecidos em formato JSON e gerar um
    relatório executivo e técnico em Português.

    Estrutura do Relatório esperada:
    1. Resumo Executivo (Visão geral de risco para diretores/gerentes)
    2. Superfície de Ataque Mapeada (Ativos e portas abertas)
    3. Análise de Vulnerabilidades e Severidade (Matriz de risco CVSS)
    4. Plano de Ação e Mitigação (Passo a passo técnico para correção)
    """


    try:
       response = client.messages.create(
          model = "claude-sonnet-5",
          max_tokens=2000,
          system=prompt_system,
          messages=[
             {
                  "role": "user",
                  "content": f"Analise o seguinte JSON de escaneamento e gere o relatório:\n\n{json.dumps(dados_scan, indent=2)}"
             }

          ]

       )

      ###### Extrai apenas o bloco de texto, ignorando ThinkiBlocks se existirem
       report_text = "".join(
          block.text for block in response.content if getattr(block, "type", "") == "text"
       )



       if report_text:
          print("[+] Análise de Inteligência concluída com sucesso!")
          return report_text
       else:
          print("[-] Nenhum bloco de texto foi retornado pela API.")
          return None


    except Exception as e:
       print(f"[-] Erro ao se comunicar com a API do Claude: {e}")
       return None
