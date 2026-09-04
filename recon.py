import socket
import sys

def resolver_host(domain):
    """
    Função para resolver o endereço IP de um dominio/subdominio
    utilizando a biblioteca nativa socket.
    """
    try:
       ip = socket.gethostbyname(domain)
       return ip
    except socket.gaierror:
       # Ocorre quando o subdominio/host não existe ou não responde ao DNS
       return None

def mapear_subdominios(dominio_alvo, lista_subdominios):
    print(f"[*] Iniciando reconhecimento em: {dominio_alvo}\n")

    resultados = {}

    for sub in lista_subdominios:
        # Concatena o subdominio ao dominio alvo (ex: api.empresa.com.br)
        alvo_completo = f"{sub}.{dominio_alvo}"
        ip = resolver_host(alvo_completo)

        if ip:
            print(f"[+] ATIVO: {alvo_completo} -> {ip}")
            resultados[alvo_completo] = ip
        else:
            print(f"[-] INATIVO: {alvo_completo}")

    return resultados

if __name__ == "__main__":
    # ALvo para testes de validação do codigo
   dominio = "google.com"

    # Wordlist simplificada de subdominios comuns para validação inicial
   wordlist_teste = ["www", "api", "dev", "mail", "admin", "test", "vpn"]

   resultado_final = mapear_subdominios(dominio, wordlist_teste)

   print("\n[=] Mapeamento Concluído:")
   print(resultado_final)
