===========================================
============= P O R T H A W K =============


<img width="1676" height="580" alt="image" src="https://github.com/user-attachments/assets/98adc807-6aa8-4c3f-92ff-e4a9f3d6ff7a" />


1. VISÃO GERAL
--------------
O PortHawk é um scanner de portas TCP de alto desempenho, projetado para ser 
robusto, moderno e eficaz. Ele combina uma interface interativa amigável com 
um backend potente que utiliza concorrência (threading) e fingerprinting para 
identificar não apenas portas abertas, mas os serviços que rodam nelas.

2. INSTALAÇÃO E REQUISITOS
--------------------------
Requisitos de Sistema:
- Python 3.7 ou superior
- Bibliotecas Externas (Instalação via terminal):
  pip install pyfiglet tqdm colorama

Como Executar:
- python porthawk.py

3. ARQUITETURA DO BACKEND (ROBUSTEZ)
------------------------------------
O "motor" do PortHawk foi otimizado através de quatro pilares técnicos:

A) Concorrência Dinâmica (ThreadPoolExecutor):
   Ajusta o número de threads automaticamente baseado no intervalo de portas,
   evitando saturação da interface de rede e perda de pacotes.

B) Banner Grabbing (Fingerprinting):
   Após detectar uma porta aberta, o script tenta capturar a "assinatura" do 
   serviço (ex: versões de SSH, Servidores Web, etc.), fornecendo mais 
   contexto do que apenas o status da porta.

C) Tratamento de Exceções de SO:
   Diferencia erros de timeout de recusas de conexão pelo firewall, garantindo
   precisão nos resultados.

D) Adaptive Threading:
   Limite de segurança de 500 threads simultâneas para proteger a integridade
   dos resultados contra Rate Limiting.

4. FUNCIONALIDADES E INTERAÇÃO
------------------------------
Interface Interativa:
- Modo 1: Comuns (1-1024) - Focado em serviços de sistema.
- Modo 2: Web (80/443)    - Focado em servidores de aplicação.
- Modo 3: Full (1-65535)   - Auditoria completa (Deep Scan).

Feedback Visual:
- Banner Verde: Estilo terminal profissional.
- ProgressBar (tqdm): Progresso em tempo real com estimativa de tempo restante.
- Logs Coloridos: Diferenciação entre portas abertas, filtradas e erros.

5. GUIA DE USO (PASSO A PASSO)
------------------------------
1. Target: Insira o IP ou Hostname (o script resolve o DNS automaticamente).
2. Range: Selecione o perfil de portas desejado (1, 2 ou 3).
3. Timeout: Padrão 0.5s. Em rede local use 0.1s. Na Internet use 0.5s a 1.0s.
4. Análise: Acompanhe os resultados e banners capturados em tempo real.
5. Resumo: Analise o relatório final de duração e lista consolidada.

6. ESPECIFICAÇÕES TÉCNICAS
--------------------------
- Protocolo:          TCP (IPv4)
- Timeout Scan:       0.5s (ajustável)
- Timeout Banner:     0.8s
- Threads Máximas:    500
- Buffer Grabbing:    1024 bytes

7. AVISO LEGAL
--------------
Este script foi desenvolvido para fins pedagógicos e de auditoria autorizada. 
O uso em redes ou sistemas sem permissão prévia é ilegal e antiético. 
O desenvolvedor não se responsabiliza pelo uso indevido da ferramenta.

===============================================================================
Copyright (c) 2026 - Romildo (thuf) | foryousec.com
===============================================================================
