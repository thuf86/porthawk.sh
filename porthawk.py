#!/usr/bin/env python3
"""
Autor: Romildo (thuf) - foryousec.com
"""

import socket
import pyfiglet
import argparse
import time
import json
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)

class ProfessionalPortScanner:
    
    def __init__(self):
        self.script_info = "Romildo (thuf) - foryousec.com"
        self.services = {
            20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Proxy"
        }
        self.open_ports = []
        self.stop_scanning = False
        self.start_time = None
        self.target_ip = None
        self.banners = {} # Armazena banners capturados
        
    def print_banner(self):
        print(f"\n{Fore.GREEN}{'='*65}")
        banner = pyfiglet.figlet_format("PORTHAWK", font="slant", width=100)
        print(f"{Fore.GREEN}{banner.rstrip()}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW} {self.script_info}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*65}{Style.RESET_ALL}\n")

    def grab_banner(self, ip, port, timeout):
        """Tenta capturar a versão do serviço (Fingerprinting)"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                # Envia um byte de teste para forçar resposta de alguns serviços
                s.send(b'Hello\r\n')
                banner = s.recv(1024).decode(errors='ignore').strip()
                if banner:
                    return banner[:50] # Limita tamanho do banner
        except:
            pass
        return None

    def scan_single_port(self, target_ip, port, timeout):
        """Backend robusto com verificação de erro do SO"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    # Se aberta, tenta capturar versão do serviço
                    banner = self.grab_banner(target_ip, port, timeout=0.8)
                    if banner: self.banners[port] = banner
                    return port
        except (socket.timeout, ConnectionRefusedError):
            pass
        except Exception:
            pass # Ignora erros de sistema/rede saturada
        return None

    # Lógica de interação mantida conforme original...
    def interactive_input(self, prompt, default=None, port=False, validate_func=None):
        default_str = f" [{default}]" if default is not None else ""
        color = Fore.CYAN if not port else Fore.YELLOW
        while True:
            value = input(f"{color}{prompt}{default_str}: {Style.RESET_ALL}").strip()
            if not value and default is not None: return default
            if port:
                try:
                    val = int(value)
                    if validate_func and not validate_func(val): continue
                    return val
                except ValueError: continue
            return value

    def resolve_target(self, target):
        try:
            resolved = socket.gethostbyname(target)
            print(f"{Fore.GREEN}✓ Alvo resolvido: {target} → {resolved}{Style.RESET_ALL}")
            return resolved
        except socket.gaierror:
            print(f"{Fore.RED}❌ Erro de DNS. Verifique o endereço.{Style.RESET_ALL}")
            sys.exit(1)

    def scan_target(self, target_ip, start_port, end_port, timeout):
        self.start_time = time.time()
        port_range = end_port - start_port + 1
        workers = min(500, max(50, port_range // 5)) # Threading balanceado
        
        print(f"{Fore.GREEN}🔍 Escaneando Alvo: {target_ip} ({start_port}-{end_port}){Style.RESET_ALL}")
        
        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(self.scan_single_port, target_ip, port, timeout): port 
                           for port in range(start_port, end_port + 1)}
                
                with tqdm(total=len(futures), desc="🔎 Progresso", unit="port",
                          bar_format="{l_bar}%s{bar}%s| {n_fmt}/{total_fmt}" % (Fore.GREEN, Fore.WHITE)) as pbar:
                    for future in as_completed(futures):
                        if self.stop_scanning: break
                        res = future.result()
                        if res:
                            self.open_ports.append(res)
                            svc = self.services.get(res, "Desconhecido")
                            info = f" | Banner: {self.banners[res]}" if res in self.banners else ""
                            print(f"{Fore.GREEN}✅ {res:5d} | {svc:<12} | ABERTA{info}{Style.RESET_ALL}")
                        pbar.update(1)
        except KeyboardInterrupt:
            self.stop_scanning = True

    def print_summary(self):
        duration = time.time() - self.start_time
        print(f"\n{Fore.MAGENTA}{'='*65}")
        print(f"📊 RELATÓRIO FINAL | Duração: {duration:.1f}s")
        print(f"{Fore.MAGENTA}{'='*65}{Style.RESET_ALL}")
        
        if self.open_ports:
            self.open_ports.sort()
            for port in self.open_ports:
                svc = self.services.get(port, "Desconhecido")
                banner = self.banners.get(port, "Sem detalhes do serviço")
                print(f" {Fore.GREEN}{port:5d}/TCP{Style.RESET_ALL} - {Fore.CYAN}{svc:<12}{Style.RESET_ALL} ({banner})")
        else:
            print(f"{Fore.RED}Nenhuma porta aberta encontrada.{Style.RESET_ALL}")

    def run(self):
        self.print_banner()
        target = self.interactive_input("🎯 Digite o IP ou DNS")
        self.target_ip = self.resolve_target(target)
        
        # Opções simplificadas para fluidez
        print(f"\n{Fore.CYAN}Range de Portas: 1:Comuns (1-1024) | 2:Web | 3:Full (1-65535){Style.RESET_ALL}")
        opt = self.interactive_input("🔢 Escolha", "1")
        
        start, end = 1, 1024
        if opt == "2": start, end = 80, 443
        elif opt == "3": start, end = 1, 65535
        
        timeout = float(self.interactive_input("⏱️ Timeout (s)", "0.5"))
        
        self.scan_target(self.target_ip, start, end, timeout)
        self.print_summary()

if __name__ == "__main__":
    ProfessionalPortScanner().run()
