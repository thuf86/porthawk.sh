#!/usr/bin/env python3
"""
PortHawk - Professional Port Scanner
Autor: Romildo (thuf) - foryousec.com

Uso responsável: execute somente em ambientes autorizados.
"""

import socket
import sys
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)


class ProfessionalPortScanner:

    def __init__(self):
        self.script_info = "Romildo (thuf) - foryousec.com"

        self.services = {
            20: "FTP-Data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
        }

        self.open_ports = []
        self.banners = {}
        self.start_time = None
        self.target_ip = None
        self.stop_event = threading.Event()

    # ===================== BANNER FIXO =====================
    def print_banner(self):
        print(Fore.GREEN + "=" * 65)
        print(Fore.GREEN + r"""
██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██████╔╝██║   ██║██████╔╝   ██║   ███████║███████║██║ █╗ ██║█████╔╝ 
██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══██║██╔══██║██║███╗██║██╔═██╗ 
██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
                                                                    
""")
        print(Fore.YELLOW + f"---- {self.script_info} ----")
        print(Fore.GREEN + "=" * 65 + Style.RESET_ALL + "\n")

    # ===================== INPUT =====================
    def interactive_input(self, prompt, default=None, numeric=False):
        default_txt = f" [{default}]" if default is not None else ""
        color = Fore.CYAN if not numeric else Fore.YELLOW

        while True:
            value = input(f"{color}{prompt}{default_txt}: {Style.RESET_ALL}").strip()
            if not value and default is not None:
                return default
            if numeric:
                try:
                    return int(value)
                except ValueError:
                    continue
            return value

    # ===================== CORE =====================
    def resolve_target(self, target):
        try:
            ip = socket.gethostbyname(target)
            print(f"{Fore.GREEN}✓ Alvo resolvido: {target} → {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}❌ Erro ao resolver DNS{Style.RESET_ALL}")
            sys.exit(1)

    def scan_port(self, ip, port, timeout):
        if self.stop_event.is_set():
            return None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    banner = self.grab_banner(ip, port, timeout)
                    return port, banner
        except OSError:
            pass
        return None

    def grab_banner(self, ip, port, timeout):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(min(timeout, 0.8))
                s.connect((ip, port))
                try:
                    data = s.recv(1024)
                    if data:
                        return data.decode(errors="ignore").strip()[:80]
                except socket.timeout:
                    pass

                s.sendall(b"Hello\r\n")
                data = s.recv(1024)
                return data.decode(errors="ignore").strip()[:80]
        except OSError:
            if port in (443, 993, 995, 8443):
                return "TLS provável (sem handshake)"
        return None

    def scan(self, ip, ports, timeout, threads):
        self.start_time = time.time()
        threads = max(20, min(threads, 200))

        print(f"\n{Fore.GREEN}🔍 Escaneando: {ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🧵 Threads: {threads} | ⏱ Timeout: {timeout}s | 🔢 Portas: {len(ports)}{Style.RESET_ALL}\n")

        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(self.scan_port, ip, p, timeout) for p in ports]

                with tqdm(total=len(futures), desc="🔎 Progresso", unit="port") as bar:
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            port, banner = result
                            self.open_ports.append(port)
                            if banner:
                                self.banners[port] = banner

                            svc = self.services.get(port, "Desconhecido")
                            info = f" | {banner}" if banner else ""
                            print(f"{Fore.GREEN}✅ {port:5d} | {svc:<12} | ABERTA{info}{Style.RESET_ALL}")

                        bar.update(1)
        except KeyboardInterrupt:
            self.stop_event.set()

    def summary(self):
        duration = time.time() - self.start_time
        print(f"\n{Fore.MAGENTA}{'=' * 65}")
        print(f"📊 RELATÓRIO FINAL | Duração: {duration:.2f}s")
        print(f"{Fore.MAGENTA}{'=' * 65}{Style.RESET_ALL}")

        if not self.open_ports:
            print(f"{Fore.RED}Nenhuma porta aberta encontrada{Style.RESET_ALL}")
            return

        for p in sorted(self.open_ports):
            svc = self.services.get(p, "Desconhecido")
            banner = self.banners.get(p, "Sem banner")
            print(f"{Fore.GREEN}{p}/TCP{Style.RESET_ALL} - {Fore.CYAN}{svc}{Style.RESET_ALL} ({banner})")

    # ===================== RUN =====================
    def run(self):
        self.print_banner()

        target = self.interactive_input("🎯 Digite o IP ou DNS")
        self.target_ip = self.resolve_target(target)

        print(f"\n{Fore.CYAN}1: Comuns (1-1024) | 2: Web | 3: Full | 4: Custom{Style.RESET_ALL}")
        opt = self.interactive_input("🔢 Escolha", "1")

        if opt == "2":
            ports = [80, 443, 8080, 8443, 3000, 5000]
        elif opt == "3":
            ports = list(range(1, 65536))
        elif opt == "4":
            start = self.interactive_input("Porta inicial", "1", True)
            end = self.interactive_input("Porta final", "1024", True)
            ports = list(range(min(start, end), max(start, end) + 1))
        else:
            ports = list(range(1, 1025))

        timeout = float(self.interactive_input("⏱ Timeout (s)", "0.5"))
        threads = int(self.interactive_input("🧵 Threads (20-200)", "120", True))

        self.scan(self.target_ip, ports, timeout, threads)
        self.summary()


if __name__ == "__main__":
    ProfessionalPortScanner().run()