import subprocess
import json
import os

def scanner_vuln(target_url):
    """
    Executa o scanner Nuclei conta uma URL/Subdominio e retorna
    as vulnerabilidades encontradas formatadas em Python.
    """
    print(f"[*] Iniciando varredura de vulnerabilidades (Nuclei) em: {target_url}")

    file_temp = "temp_nuclei.json"

    # Comando executado no Kali
    command = [
        "nuclei",
        "-u", target_url,
        "-severity", "low,medium,high,critical",
        "-json-export", file_temp,
        "-silent"


    ]
    try:
       # Executa o comando no SO atraves do Python
       subprocess.run(command, check=True)

       vulnerability = []

       # Se o Nuclei encontrou falhas e gerou o arquivo temporario
       if os.path.exists(file_temp):
           with open(file_temp, "r") as f:
              for line in f:
                  line_clear = line.strip()
                  if line_clear:
                     dado_parsed = json.loads(line_clear)
       # Filro SÊNIOR: Apenas adiciona se for um dicionário VÁLIDO

                     if isinstance(dado_parsed, dict) and dado_parsed:
                      vulnerability.append(dados_parsed)

       # Limpa o arquivo temporario no sistema
           os.remove(file_temp)


       print(f"[+] Varredura concluída. Falhas/alertas encontrados: {len(vulnerability)}")
       return vulnerability

    except subprocess.CalledProcessError as e:
       print(f"[-] Erro ao executar o Nuclei: {e}")
       return []
    except Exception as e:
       print(f"[-] Erro inesperado no scanner: {e}")
       return []


if __name__ == "__main__":
    # Site de testes propositalmente vulneravel para validação
    target_test = "http://testphp.vulnweb.com/"

    findings = scanner_vuln(target_test)

    print("\n[=] Resultado das Vulnerabilidades Encontradas:")
    for item in findings:
    # Tratamento defensivo: verifica se o item é um dicionário antes de extrair
           if isinstance(item, dict):
              info = item.get("info", {})

           # Se "info" for uma lista, pegamos o primeiro elemento
              if isinstance(info, list) and len(info) > 0:
                  info = info[0]

              if isinstance(info,dict):
                     severityy = info.get("severity", "info").upper()
                     namee_failed = info.get("name", "unknown")
                     print(f"-  [{severityy}] {namee_failed}")
              else:
                      print(f" - [INFO] Achado extraído: {item}")
           else:
               print(f"- [INFO] Achado genérico: {item}") 
