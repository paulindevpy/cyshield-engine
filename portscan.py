import asyncio
import socket


async def scan_single_port(ip, port, timeout=1.0):
  """Testa uma única porta de forma assíncrona."""
  try:
    conn = asyncio.open_connection(ip, port)
    reader, writer = await asyncio.wait_for(conn, timeout=timeout)
    writer.close()
    await writer.wait_closed()
    print(f"[+] Porta {port} ABERTA em {ip}")
    return port
  except (asyncio.TimeoutError, OSError):
    return None


async def scanner_ports(ip_target, list_ports=[21, 22, 80, 443, 8080]):
  """Orquestra a varredura assíncrona das portas."""
  print(f"[*] Escaneando portas em {ip_target}...")
  tasks = [scan_single_port(ip_target, p) for p in list_ports]
  results = await asyncio.gather(*tasks)
  return [p for p in results if p is not None]
