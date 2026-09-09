import asyncio
import socket

def check_port_sync(ip_target, port, timeout=3.5):
    """
    Testa a conexão TCP em nível de socket de forma direta e confiavel.
    Retorna a porta se aberta (connect_ex == 0), senão None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
       result = sock.connect_ex((ip_target, port))
       if result == 0:
          print(f"[+] Porta {port} ABERTA em {ip_target}")
          return port
    except Exception:
       pass
    finally:
       sock.close()
    return None


async def _test_port_async(loop, sem, ip_target, port):
    """
    Testa uma única porta TCP de forma assícrona
    Retorna o número da porta se estiver ABERTA, ou None se fechada/filtrada.
    """
    return await loop.run_in_executor(None, lambda: check_port_sync(ip_target, port))


async def scanner_port_async(ip_target, list_ports):
   """Orquestra o escaneamento paralelo usando o Loop de Eventos do asyncio."""
   print(f"[*] [ASYNC] Varredura rápida de portas em: {ip_target}")
   loop = asyncio.get_running_loop()
   sem = asyncio.Semaphore(5)

   tasks = [_test_port_async(loop, sem, ip_target, port) for port in list_ports]
   result = await asyncio.gather(*tasks)

   open_ports = [p for p in result if p is not None]
   return open_ports

def scanner_ports(ip_target, list_ports):
    """Ponto de entrada síncrono mantido para compatibilidade com o cyshield_core.py."""
    return asyncio.run(scanner_port_async(ip_target, list_ports))


if __name__ == "__main__":
# Test rápido
     ip_test = "scanme.nmap.org"
     ports_test = [21, 22, 80, 443, 8080, 3306]
     ports = scanner_ports(ip_test, ports_test)
     print(f"\n[=] Portas abertas encontradas: {ports}")


  #  for ports in list_ports:
    #### Cria o socket TCP
      #  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     #    sock.settimeout(1.0) # Timeout de 1 segundo por porta


    #### Tenta a conexão (0 significa sucesso / porta aberta)
    #    result = sock.connect_ex((ip_target, ports))
   #     if result == 0:
  #         print(f"[+] Porta {ports} ABERTA em {ip_target}")
 #          open_ports.append(ports)
#
  #      sock.close()


 #   return open_ports

# if __name__ == "__main__":
# Teste isolado do módulo
#     ip_test = "127.0.0.1"
#     ports_test = [21, 22, 80, 443, 3306, 8080]

#     found_ports = scanner_ports(ip_test, ports_test)
#     print(f"\n[=] Portas abertas encontradas: {found_ports}")
