import subprocess
import json
import os

import subprocess
import json

def scanner_vuln(target_url):
    """
    Executa o Nuclei e retorna findings parseados.
    v2: usa -jsonl no stdout (padrão atual do nuclei), sem arquivo temporário.
    """
    print(f"[*] Iniciando varredura de vulnerabilidades (Nuclei) em: {target_url}")

    command = [
        "nuclei",
        "-u", target_url,
        "-severity", "low,medium,high,critical",
        "-jsonl",          # JSON lines no stdout (substitui -json-export)
        "-silent",
        "-nc",             # sem cor no output (essencial para o parse!)
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        vulnerabilities = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                dado = json.loads(line)
                if isinstance(dado, dict) and dado.get("info"):
                    vulnerabilities.append(dado)
            except json.JSONDecodeError:
                continue  # linha não-JSON (banner, etc.)

        print(f"[+] Varredura concluída. Falhas encontradas: {len(vulnerabilities)}")
        return vulnerabilities

    except subprocess.TimeoutExpired:
        print(f"[!] Nuclei timeout em {target_url} (600s).")
        return []
    except FileNotFoundError:
        print("[!] Nuclei não encontrado. Instale: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        return []
    except Exception as e:
        print(f"[!] Erro inesperado no scanner: {e}")
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

