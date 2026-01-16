import socket
import pyfiglet
from concurrent.futures import ThreadPoolExecutor

# Informacoes do script
script_info = "Nome: Romildo (thuf)    Site: helptecinfo.com"

# Exibindo o banner
print("\n\n======================================")
banner = pyfiglet.figlet_format("SCANNER")
print(banner)
print(script_info)
print("======================================\n")

# Recebendo o endereco/IP e validando
ip_address = input('Insira o endereco ou IP a ser escaneado: ')
try:
    resolved_ip = socket.gethostbyname(ip_address)
except socket.gaierror:
    print("Erro: Endereco invalido. Verifique o IP ou hostname.")
    exit()

# Recebendo intervalo de portas e validando
try:
    start_port = int(input('Insira a porta inicial (padrao 1): ') or 1)
    end_port = int(input('Insira a porta final (padrao 1024): ') or 1024)
    if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
        raise ValueError("As portas devem estar entre 0 e 65535.")
    if start_port > end_port:
        raise ValueError("A porta inicial deve ser menor ou igual a porta final.")
except ValueError as ve:
    print(f"Erro: {ve}")
    exit()

def scan_port(ip, port):
    """Funcao para verificar se uma porta esta aberta"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)  # Tempo de espera reduzido
            if sock.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None

def scan_ports(ip_address, start_port, end_port):
    """Funcao principal para escanear portas em threads"""
    open_ports = []
    print(f"\nEscaneando {ip_address} ({resolved_ip}) nas portas {start_port}-{end_port}...\n")

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip_address, port) for port in range(start_port, end_port + 1)]
        for future in futures:
            port = future.result()
            if port:
                open_ports.append(port)
                print(f"Porta {port} esta aberta.")

    if open_ports:
        print(f"\nTotal de portas abertas: {len(open_ports)}. Portas: {', '.join(map(str, open_ports))}")
    else:
        print("\nNenhuma porta aberta encontrada.")

# Executando o scanner
scan_ports(resolved_ip, start_port, end_port)
