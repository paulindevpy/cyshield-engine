import socket

def scanner_ports(ip_target, list_ports):
    """
    Realiza o escaneamento de portas TCP em um IP alvo.
    Retorna uma lista com as portas que estão abertas.
    """
    print(f"[*] Iniciando o escaneamento de portas no IP: {ip_target}")
    open_ports = []


    for ports in list_ports:
    #### Cria o socket TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0) # Timeout de 1 segundo por porta


    #### Tenta a conexão (0 significa sucesso / porta aberta)
        result = sock.connect_ex((ip_target, ports))
        if result == 0:
           print(f"[+] Porta {ports} ABERTA em {ip_target}")
           open_ports.append(ports)

        sock.close()


    return open_ports

if __name__ == "__main__":
# Teste isolado do módulo
     ip_test = "127.0.0.1"
     ports_test = [21, 22, 80, 443, 3306, 8080]

     found_ports = scanner_ports(ip_test, ports_test)
     print(f"\n[=] Portas abertas encontradas: {found_ports}")
