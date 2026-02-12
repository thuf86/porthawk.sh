#!/usr/bin/env python3
"""
PortHawk - Professional Port Scanner
"""

import socket
import sys
import time
import json
import csv
import re
import threading
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue

from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)


class ProfessionalPortScanner:

    def __init__(self):
        self.script_info = "Romildo (thuf) - foryousec.com"
        self.version = "3.0"

        self.services = {
            # Portas bem conhecidas (1-1023)
            1: "TCPMUX",
            5: "RJE",
            7: "Echo",
            9: "Discard",
            13: "Daytime",
            17: "QOTD",
            19: "Chargen",
            20: "FTP-Data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            37: "Time",
            42: "WINS",
            43: "Whois",
            49: "TACACS",
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            69: "TFTP",
            70: "Gopher",
            79: "Finger",
            80: "HTTP",
            88: "Kerberos",
            102: "MS-Exchange",
            110: "POP3",
            111: "RPCbind",
            113: "Ident",
            119: "NNTP",
            123: "NTP",
            135: "MS-RPC",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            139: "NetBIOS-SSN",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-Trap",
            177: "XDMCP",
            179: "BGP",
            194: "IRC",
            201: "AppleTalk",
            264: "BGMP",
            318: "TSP",
            381: "HP-Openview",
            383: "HP-Openview",
            389: "LDAP",
            443: "HTTPS",
            445: "SMB",
            464: "Kerberos-Passwd",
            465: "SMTPS",
            497: "Dantz-Retrospect",
            500: "ISAKMP",
            512: "Exec",
            513: "Login",
            514: "Shell",
            515: "Printer",
            520: "RIP",
            521: "RIPng",
            523: "DB2",
            524: "NCP",
            530: "RPC",
            548: "AFP",
            554: "RTSP",
            563: "NNTPS",
            587: "SMTP-Submission",
            591: "FileMaker",
            593: "MS-DCOM",
            631: "IPP",
            636: "LDAPS",
            646: "LDP",
            648: "RRP",
            666: "Doom",
            674: "ACAP",
            691: "MS-Exchange",
            860: "iSCSI",
            873: "RSYNC",
            902: "VMware",
            989: "FTPS-Data",
            990: "FTPS",
            991: "NAS",
            992: "TelnetS",
            993: "IMAPS",
            994: "IRCS",
            995: "POP3S",
            # Portas registradas (1024-49151)
            1080: "SOCKS",
            1194: "OpenVPN",
            1214: "Kazaa",
            1241: "Nessus",
            1311: "Dell-OpenManage",
            1337: "WASTE",
            1433: "MSSQL",
            1434: "MSSQL-Monitor",
            1512: "WINS",
            1521: "Oracle",
            1589: "Cisco-VQP",
            1701: "L2TP",
            1723: "PPTP",
            1863: "MSN",
            1900: "UPnP",
            1984: "BigBrother",
            2000: "Cisco-SCCP",
            2049: "NFS",
            2082: "cPanel",
            2083: "cPanel-SSL",
            2086: "WHM",
            2087: "WHM-SSL",
            2095: "cPanel-Webmail",
            2096: "cPanel-Webmail-SSL",
            2101: "RTCM",
            2222: "DirectAdmin",
            2302: "Halo",
            2483: "Oracle-SSL",
            2484: "Oracle-SSL",
            2745: "Bagle-H",
            2967: "Symantec-AV",
            3050: "Interbase",
            3074: "Xbox-Live",
            3127: "MyDoom",
            3128: "Squid-Proxy",
            3222: "GLBP",
            3260: "iSCSI-Target",
            3268: "MS-GlobalCatalog",
            3269: "MS-GlobalCatalog-SSL",
            3306: "MySQL",
            3389: "RDP",
            3689: "DAAP",
            3690: "SVN",
            3724: "Blizzard",
            3784: "Ventrilo",
            4000: "Diablo2",
            4333: "mSQL",
            4444: "Blaster",
            4662: "eMule",
            4672: "eMule-UDP",
            4899: "Radmin",
            5000: "UPnP",
            5001: "iPerf",
            5004: "RTP",
            5005: "RTCP",
            5050: "Yahoo-Messenger",
            5060: "SIP",
            5190: "AIM",
            5222: "XMPP",
            5223: "XMPP-SSL",
            5432: "PostgreSQL",
            5500: "VNC-Server",
            5554: "Sasser",
            5631: "PCAnywhere",
            5632: "PCAnywhere",
            5800: "VNC-Web",
            5900: "VNC",
            5901: "VNC-1",
            5902: "VNC-2",
            5903: "VNC-3",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS",
            6000: "X11",
            6001: "X11-1",
            6112: "Battle.net",
            6129: "DameWare",
            6379: "Redis",
            6500: "GameSRV",
            6566: "SANE",
            6588: "AnalogX",
            6600: "MS-SPP",
            6665: "IRC",
            6666: "IRC",
            6667: "IRC",
            6668: "IRC",
            6669: "IRC",
            6679: "IRC-SSL",
            6697: "IRC-SSL",
            8000: "HTTP-Alt",
            8008: "HTTP-Alt",
            8009: "AJP",
            8080: "HTTP-Proxy",
            8081: "HTTP-Alt",
            8086: "Kaspersky-AV",
            8087: "Kaspersky-AV",
            8088: "Radan-HTTP",
            8118: "Privoxy",
            8123: "Polipo",
            8200: "VMware-Auth",
            8291: "Winbox",
            8292: "Bloomberg",
            8443: "HTTPS-Alt",
            8500: "ColdFusion",
            8686: "Sun-MSG",
            9000: "SonarQube",
            9001: "Tor-ORPort",
            9042: "Cassandra",
            9050: "Tor-Socks",
            9060: "Webmin",
            9090: "WebSM",
            9100: "RAW-Print",
            9150: "Tor-Browser",
            9200: "Elasticsearch",
            9418: "Git",
            9800: "WebDAV",
            9999: "Urchin",
            10000: "Webmin",
            11211: "Memcached",
            12345: "NetBus",
            13720: "NetBackup",
            13721: "NetBackup",
            19226: "AdminSecure",
            19638: "Ensim",
            20000: "Usermin",
            22222: "DirecTV",
            27017: "MongoDB",
            27018: "MongoDB-Shard",
            27019: "MongoDB-Config",
            28017: "MongoDB-Web",
            28717: "MongoDB-Alt",
            31337: "BackOrifice",
            33434: "Traceroute",
            49152: "Windows-RPC",
            49153: "Windows-RPC",
            49154: "Windows-RPC",
            49155: "Windows-RPC",
        }

        # Serviços UDP específicos
        self.udp_services = {
            53: "DNS",
            67: "DHCP",
            68: "DHCP",
            69: "TFTP",
            123: "NTP",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            161: "SNMP",
            162: "SNMP-Trap",
            500: "ISAKMP",
            514: "Syslog",
            520: "RIP",
            521: "RIPng",
            1900: "UPnP",
            33434: "Traceroute",
            4672: "eMule-UDP",
        }

        # Probes específicos por protocolo (serviços que não falam primeiro)
        self.probes = {
            80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            25: b"EHLO scanner\r\n",
            587: b"EHLO scanner\r\n",
            21: b"\r\n",
            110: b"\r\n",
            143: b"\r\n",
        }

        # Probes UDP
        self.udp_probes = {
            53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
            161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
            123: b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
        }

        # Serviços que sempre falam primeiro (não enviar probe)
        self.speak_first = {22, 23, 220}

        self.open_ports = []
        self.udp_open_ports = []
        self.banners = {}
        self.udp_banners = {}
        self.closed_ports = []
        self.filtered_ports = []
        self.start_time = None
        self.target_ip = None
        self.target_host = None
        self.stop_event = threading.Event()
        self.result_queue = Queue()
        self.quiet_mode = False
        self.output_file = None

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
        print(Fore.CYAN + f"---- Version {self.version} ----")
        print(Fore.GREEN + "=" * 65 + Style.RESET_ALL + "\n")

    # ===================== INPUT =====================
    def interactive_input(self, prompt, default=None, numeric=False):
        default_txt = f" [{default}]" if default is not None else ""
        color = Fore.CYAN if not numeric else Fore.YELLOW

        while True:
            try:
                value = input(f"{color}{prompt}{default_txt}: {Style.RESET_ALL}").strip()
                if not value and default is not None:
                    return default
                if numeric:
                    try:
                        return int(value)
                    except ValueError:
                        print(f"{Fore.RED}⚠️ Valor numérico inválido{Style.RESET_ALL}")
                        continue
                return value
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}⚠️ Interrompido pelo usuário{Style.RESET_ALL}")
                sys.exit(0)

    def validate_target(self, target):
        """Valida se o target é um IP ou hostname válido"""
        if not target:
            raise ValueError("Target não pode ser vazio")
        
        # Remove protocolo se existir
        target = re.sub(r'^https?://', '', target)
        target = target.rstrip('/')
        
        # Validação básica de caracteres
        if not re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9\.]*[a-zA-Z0-9]$', target):
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
                raise ValueError(f"Target inválido: {target}")
        
        return target

    # ===================== CORE =====================
    def resolve_target(self, target):
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(f"{Fore.GREEN}✓ Alvo resolvido: {target} → {ip}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}✓ Alvo: {ip}{Style.RESET_ALL}")
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}❌ Erro ao resolver DNS: {target}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}❌ Erro: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def grab_banner_unified(self, sock, port):
        """Banner grabbing unificado - recebe primeiro, depois envia probe se necessário"""
        banner = None
        
        try:
            # Primeiro tenta receber (serviços que falam primeiro: SSH, FTP, Telnet)
            sock.settimeout(1.0)
            try:
                data = sock.recv(1024)
                if data:
                    banner = data.decode(errors="ignore").strip()
                    return banner[:200] if banner else None
            except socket.timeout:
                pass
            
            # Se não recebeu nada e não é serviço que fala primeiro, envia probe
            if port not in self.speak_first:
                probe = self.probes.get(port, b"\r\n")
                sock.sendall(probe)
                
                try:
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode(errors="ignore").strip()
                        return banner[:200] if banner else None
                except socket.timeout:
                    pass
            
            # Para portas TLS comuns sem banner
            if port in (443, 993, 995, 465, 636, 8443):
                return "TLS/SSL (handshake não realizado)"
                
        except Exception:
            pass
        
        return banner

    def scan_port_tcp(self, ip, port, timeout, retry=1):
        """Scan de porta TCP com retry logic"""
        if self.stop_event.is_set():
            return None

        attempts = 0
        while attempts <= retry:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((ip, port))
                    
                    if result == 0:
                        # Porta aberta - fazer banner grabbing na mesma conexão
                        banner = self.grab_banner_unified(s, port)
                        return (port, "open", banner)
                    elif result == 111:  # Connection refused
                        return (port, "closed", None)
                    else:
                        # Outros erros (pode ser filtrado)
                        if attempts == retry:
                            return (port, "filtered", None)
                        
            except socket.timeout:
                if attempts == retry:
                    return (port, "filtered", None)
            except OSError as e:
                if e.errno == 1:  # Operation not permitted
                    return (port, "error", "Permission denied")
                if attempts == retry:
                    return (port, "error", str(e))
            except Exception:
                if attempts == retry:
                    return (port, "error", "Unknown error")
            
            attempts += 1
            if attempts <= retry:
                time.sleep(0.1)  # Pequeno delay entre retries
        
        return None

    def scan_port_udp(self, ip, port, timeout, retry=1):
        """Scan de porta UDP"""
        if self.stop_event.is_set():
            return None

        attempts = 0
        while attempts <= retry:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    
                    # Envia probe específico ou genérico
                    probe = self.udp_probes.get(port, b"\x00" * 4)
                    s.sendto(probe, (ip, port))
                    
                    try:
                        data, addr = s.recvfrom(1024)
                        if data:
                            banner = data.decode(errors="ignore").strip()[:200]
                            return (port, "open", banner)
                    except socket.timeout:
                        # Timeout pode significar porta aberta (sem resposta) ou filtrada
                        # Verificamos enviando para porta fechada (ICMP unreachable)
                        pass
                    
                    # Tenta novamente para detectar closed vs open|filtered
                    try:
                        s.settimeout(0.5)
                        s.sendto(probe, (ip, port))
                        s.recvfrom(1024)
                    except socket.timeout:
                        # Sem resposta - pode ser open ou filtered
                        if attempts == retry:
                            return (port, "open|filtered", None)
                    except ConnectionRefusedError:
                        # ICMP Port Unreachable = porta fechada
                        return (port, "closed", None)
                    except Exception:
                        if attempts == retry:
                            return (port, "open|filtered", None)
                        
            except PermissionError:
                return (port, "error", "Permission denied (need root)")
            except Exception as e:
                if attempts == retry:
                    return (port, "error", str(e))
            
            attempts += 1
            if attempts <= retry:
                time.sleep(0.2)
        
        return None

    def process_results(self, udp=False):
        """Processa resultados da queue para não quebrar o tqdm"""
        prefix = "UDP" if udp else "TCP"
        banner_dict = self.udp_banners if udp else self.banners
        open_list = self.udp_open_ports if udp else self.open_ports
        
        while not self.result_queue.empty():
            result = self.result_queue.get()
            if result:
                port, status, banner = result
                
                if status == "open":
                    open_list.append(port)
                    if banner:
                        banner_dict[port] = banner
                    
                    svc = self.services.get(port, self.udp_services.get(port, "Desconhecido"))
                    info = f" | {banner}" if banner else ""
                    
                    if not self.quiet_mode:
                        proto_color = Fore.MAGENTA if udp else Fore.GREEN
                        print(f"\r{proto_color}✅ {prefix} {port:5d} | {svc:<12} | ABERTA{info}{Style.RESET_ALL}")
                elif status == "open|filtered":
                    open_list.append(port)
                    svc = self.services.get(port, self.udp_services.get(port, "Desconhecido"))
                    if not self.quiet_mode:
                        print(f"\r{Fore.YELLOW}⚠️  {prefix} {port:5d} | {svc:<12} | OPEN|FILTERED{Style.RESET_ALL}")
                elif status == "closed":
                    self.closed_ports.append((prefix, port))
                elif status in ("filtered", "error"):
                    self.filtered_ports.append((prefix, port))

    def scan(self, ip, ports, timeout, threads, retry=0, delay=0, udp=False):
        self.start_time = time.time()
        threads = max(10, min(threads, 300))
        
        # Separar portas prioritárias (comuns) para scanear primeiro
        if udp:
            common_ports = set(self.udp_services.keys())
        else:
            common_ports = set(self.services.keys())
        
        priority_ports = [p for p in ports if p in common_ports]
        other_ports = [p for p in ports if p not in common_ports]
        
        # Ordenar prioridade por número da porta
        priority_ports.sort()
        other_ports.sort()
        
        ordered_ports = priority_ports + other_ports

        protocol = "UDP" if udp else "TCP"
        
        if not self.quiet_mode:
            print(f"\n{Fore.GREEN}🔍 Escaneando {protocol}: {ip}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🧵 Threads: {threads} | ⏱ Timeout: {timeout}s | 🔢 Portas: {len(ordered_ports)}{Style.RESET_ALL}")
            if retry > 0:
                print(f"{Fore.CYAN}🔄 Retry: {retry}x | ⏱ Delay: {delay}ms{Style.RESET_ALL}")
            print()

        completed = 0
        executor = None
        scan_func = self.scan_port_udp if udp else self.scan_port_tcp
        
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                # Submeter todas as tarefas
                future_to_port = {
                    executor.submit(scan_func, ip, p, timeout, retry): p 
                    for p in ordered_ports
                }
                
                # Barra de progresso
                desc = f"🔎 {protocol} Progresso"
                with tqdm(total=len(future_to_port), desc=desc, 
                         unit="port", disable=self.quiet_mode, ncols=70) as bar:
                    
                    for future in as_completed(future_to_port):
                        if self.stop_event.is_set():
                            break
                            
                        result = future.result()
                        if result:
                            self.result_queue.put(result)
                            
                        completed += 1
                        
                        # Processar resultados a cada 10 portas ou no final
                        if completed % 10 == 0 or completed == len(future_to_port):
                            self.process_results(udp)
                        
                        bar.update(1)
                        
                        # Rate limiting
                        if delay > 0:
                            time.sleep(delay / 1000.0)
                            
        except KeyboardInterrupt:
            self.stop_event.set()
            print(f"\n{Fore.YELLOW}⚠️ Scan interrompido pelo usuário!{Style.RESET_ALL}")
            if executor:
                executor.shutdown(wait=False)
            # Processar resultados pendentes
            self.process_results(udp)
            
        # Processar resultados finais
        self.process_results(udp)

    def summary(self, scan_udp=False):
        duration = time.time() - self.start_time
        
        if not self.quiet_mode:
            print(f"\n{Fore.MAGENTA}{'=' * 65}")
            print(f"📊 RELATÓRIO FINAL | Duração: {duration:.2f}s")
            print(f"{Fore.MAGENTA}{'=' * 65}{Style.RESET_ALL}")

        # TCP Results
        if self.open_ports:
            if not self.quiet_mode:
                print(f"\n{Fore.CYAN}🟢 PORTAS TCP ABERTAS:{Style.RESET_ALL}")
            for p in sorted(self.open_ports):
                svc = self.services.get(p, "Desconhecido")
                banner = self.banners.get(p, "Sem banner")
                
                if not self.quiet_mode:
                    display_banner = banner[:60] + "..." if len(banner) > 60 else banner
                    print(f"{Fore.GREEN}{p}/TCP{Style.RESET_ALL} - {Fore.CYAN}{svc}{Style.RESET_ALL} ({display_banner})")

        # UDP Results
        if scan_udp and self.udp_open_ports:
            if not self.quiet_mode:
                print(f"\n{Fore.CYAN}🟣 PORTAS UDP ABERTAS:{Style.RESET_ALL}")
            for p in sorted(self.udp_open_ports):
                svc = self.udp_services.get(p, self.services.get(p, "Desconhecido"))
                banner = self.udp_banners.get(p, "Sem banner")
                
                if not self.quiet_mode:
                    display_banner = banner[:60] + "..." if len(banner) > 60 else banner
                    print(f"{Fore.MAGENTA}{p}/UDP{Style.RESET_ALL} - {Fore.CYAN}{svc}{Style.RESET_ALL} ({display_banner})")

        if not self.open_ports and not (scan_udp and self.udp_open_ports):
            if not self.quiet_mode:
                print(f"{Fore.RED}❌ Nenhuma porta aberta encontrada{Style.RESET_ALL}")

        # Estatísticas
        total_tcp = len(self.open_ports) + len([p for t, p in self.closed_ports if t == "TCP"]) + len([p for t, p in self.filtered_ports if t == "TCP"])
        if scan_udp:
            total_udp = len(self.udp_open_ports) + len([p for t, p in self.closed_ports if t == "UDP"]) + len([p for t, p in self.filtered_ports if t == "UDP"])
        else:
            total_udp = 0
            
        if not self.quiet_mode and total_tcp > 0:
            print(f"\n{Fore.CYAN}📈 Estatísticas TCP:{Style.RESET_ALL}")
            tcp_closed = len([p for t, p in self.closed_ports if t == "TCP"])
            tcp_filtered = len([p for t, p in self.filtered_ports if t == "TCP"])
            print(f"   Abertas: {len(self.open_ports)} | Fechadas: {tcp_closed} | Filtradas: {tcp_filtered}")
            
            if scan_udp:
                print(f"\n{Fore.CYAN}📈 Estatísticas UDP:{Style.RESET_ALL}")
                udp_closed = len([p for t, p in self.closed_ports if t == "UDP"])
                udp_filtered = len([p for t, p in self.filtered_ports if t == "UDP"])
                print(f"   Abertas: {len(self.udp_open_ports)} | Fechadas: {udp_closed} | Filtradas: {udp_filtered}")

        return {
            "target": self.target_host,
            "ip": self.target_ip,
            "duration": duration,
            "tcp_open_ports": sorted(self.open_ports),
            "udp_open_ports": sorted(self.udp_open_ports) if scan_udp else [],
            "tcp_banners": self.banners,
            "udp_banners": self.udp_banners if scan_udp else {},
            "closed_count": len(self.closed_ports),
            "filtered_count": len(self.filtered_ports),
            "total_scanned": total_tcp + total_udp
        }

    def export_results(self, data, formats=None):
        """Exporta resultados em múltiplos formatos"""
        if not formats:
            formats = []
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_base = f"porthawk_scan_{self.target_host.replace('.', '_')}_{timestamp}"
        
        exported_files = []
        
        # JSON
        if "json" in formats or "all" in formats:
            json_file = f"{filename_base}.json"
            try:
                with open(json_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                exported_files.append(json_file)
                if not self.quiet_mode:
                    print(f"{Fore.GREEN}✓ Exportado: {json_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}❌ Erro ao exportar JSON: {e}{Style.RESET_ALL}")
        
        # CSV
        if "csv" in formats or "all" in formats:
            csv_file = f"{filename_base}.csv"
            try:
                with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Porta', 'Protocolo', 'Serviço', 'Banner', 'Status'])
                    for port in sorted(self.open_ports):
                        svc = self.services.get(port, "Desconhecido")
                        banner = self.banners.get(port, "")
                        writer.writerow([port, 'TCP', svc, banner, 'Aberta'])
                    for port in sorted(self.udp_open_ports):
                        svc = self.udp_services.get(port, self.services.get(port, "Desconhecido"))
                        banner = self.udp_banners.get(port, "")
                        writer.writerow([port, 'UDP', svc, banner, 'Aberta'])
                exported_files.append(csv_file)
                if not self.quiet_mode:
                    print(f"{Fore.GREEN}✓ Exportado: {csv_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}❌ Erro ao exportar CSV: {e}{Style.RESET_ALL}")
        
        # TXT
        if "txt" in formats or "all" in formats:
            txt_file = f"{filename_base}.txt"
            try:
                with open(txt_file, 'w', encoding='utf-8') as f:
                    f.write(f"PortHawk Scan Report\n")
                    f.write(f"=" * 50 + "\n")
                    f.write(f"Target: {data['target']} ({data['ip']})\n")
                    f.write(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Duração: {data['duration']:.2f}s\n")
                    f.write(f"Portas TCP abertas: {len(data['tcp_open_ports'])}\n")
                    if data['udp_open_ports']:
                        f.write(f"Portas UDP abertas: {len(data['udp_open_ports'])}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    if data['tcp_open_ports']:
                        f.write("[TCP Ports]\n")
                        for port in sorted(self.open_ports):
                            svc = self.services.get(port, "Desconhecido")
                            banner = self.banners.get(port, "Sem banner")
                            f.write(f"{port}/tcp  {svc:15}  {banner}\n")
                    
                    if data['udp_open_ports']:
                        f.write("\n[UDP Ports]\n")
                        for port in sorted(self.udp_open_ports):
                            svc = self.udp_services.get(port, self.services.get(port, "Desconhecido"))
                            banner = self.udp_banners.get(port, "Sem banner")
                            f.write(f"{port}/udp  {svc:15}  {banner}\n")
                
                exported_files.append(txt_file)
                if not self.quiet_mode:
                    print(f"{Fore.GREEN}✓ Exportado: {txt_file}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}❌ Erro ao exportar TXT: {e}{Style.RESET_ALL}")
        
        return exported_files

    # ===================== RUN =====================
    def run(self):
        self.print_banner()

        target = self.interactive_input("🎯 Digite o IP ou DNS")
        
        try:
            target = self.validate_target(target)
            self.target_host = target
            self.target_ip = self.resolve_target(target)
        except ValueError as e:
            print(f"{Fore.RED}❌ {e}{Style.RESET_ALL}")
            sys.exit(1)

        print(f"\n{Fore.CYAN}1: Comuns TCP (1-1024) | 2: Web | 3: Full TCP | 4: Custom{Style.RESET_ALL}")
        print(f"{Fore.CYAN}5: Top 100 | 6: UDP Common | 7: TCP+UDP Combined{Style.RESET_ALL}")
        opt = self.interactive_input("🔢 Escolha", "1")

        scan_udp = False
        udp_ports = []
        
        if opt == "2":
            ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000]
        elif opt == "3":
            confirm = self.interactive_input(f"{Fore.YELLOW}⚠️ Scan full pode demorar muito. Continuar? (s/n){Style.RESET_ALL}", "n")
            if confirm.lower() != 's':
                print(f"{Fore.YELLOW}Cancelado. Usando modo comum.{Style.RESET_ALL}")
                ports = list(range(1, 1025))
            else:
                ports = list(range(1, 65536))
        elif opt == "4":
            start = self.interactive_input("Porta inicial", "1", True)
            end = self.interactive_input("Porta final", "1024", True)
            ports = list(range(min(start, end), max(start, end) + 1))
        elif opt == "5":
            # Top 100 portas mais comuns
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
                     13, 17, 19, 37, 42, 69, 79, 88, 102, 108, 115, 118, 123, 137, 138, 161, 162, 179, 194, 220, 264,
                     389, 427, 443, 445, 465, 500, 514, 515, 520, 521, 523, 548, 554, 587, 631, 636, 646, 666, 873,
                     902, 989, 990, 992, 993, 995, 1194, 1241, 1433, 1434, 1512, 1521, 1701, 1723, 1863, 2082, 2083,
                     2086, 2087, 2095, 2096, 2101, 2222, 2483, 2484, 2745, 2967, 3050, 3074, 3127, 3128, 3306, 3389,
                     3689, 3690, 3724, 4000, 4333, 4444, 4662, 4899, 5000, 5001, 5004, 5060, 5190, 5222, 5432, 5500]
        elif opt == "6":
            # UDP Common ports
            ports = []
            udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900, 33434]
            scan_udp = True
        elif opt == "7":
            # TCP + UDP Combined
            ports = list(range(1, 1025))
            udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900, 33434]
            scan_udp = True
        else:
            ports = list(range(1, 1025))

        # Se escolheu UDP, perguntar portas adicionais
        if scan_udp and not udp_ports:
            print(f"{Fore.CYAN}Portas UDP comuns: 53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900{Style.RESET_ALL}")
            udp_input = self.interactive_input("Portas UDP (vírgula separada, ou 'default')", "default")
            if udp_input == "default":
                udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900, 33434]
            else:
                try:
                    udp_ports = [int(p.strip()) for p in udp_input.split(",")]
                except ValueError:
                    print(f"{Fore.YELLOW}⚠️ Portas inválidas, usando default{Style.RESET_ALL}")
                    udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1900, 33434]

        timeout = float(self.interactive_input("⏱ Timeout (s)", "0.5"))
        threads = int(self.interactive_input("🧵 Threads (10-300)", "100", True))
        retry = int(self.interactive_input("🔄 Retry (0-3)", "0", True))
        delay = int(self.interactive_input("⏱ Delay entre reqs (ms)", "0", True))
        
        # Opções de exportação
        print(f"\n{Fore.CYAN}Formatos de exportação:{Style.RESET_ALL}")
        print("  none: Nenhum | json: JSON | csv: CSV | txt: Texto | all: Todos")
        export_opt = self.interactive_input("💾 Exportar como", "none")
        
        if export_opt.lower() == "none":
            export_formats = []
        else:
            export_formats = [export_opt.lower()]

        # Modo silencioso
        quiet = self.interactive_input("🔇 Modo silencioso (s/n)", "n")
        self.quiet_mode = quiet.lower() == 's'

        # Executar scan TCP
        if ports:
            self.scan(self.target_ip, ports, timeout, threads, retry, delay, udp=False)
        
        # Executar scan UDP
        if scan_udp and udp_ports:
            print(f"\n{Fore.CYAN}Iniciando scan UDP...{Style.RESET_ALL}")
            self.scan(self.target_ip, udp_ports, timeout * 2, threads, retry, delay, udp=True)
        
        # Mostrar resumo
        scan_data = self.summary(scan_udp=scan_udp)
        
        # Exportar se solicitado
        if export_formats:
            print()
            self.export_results(scan_data, export_formats)

        if not self.quiet_mode:
            print(f"\n{Fore.GREEN}✓ Scan completado!{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        ProfessionalPortScanner().run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️ Programa interrompido{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Erro fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)
