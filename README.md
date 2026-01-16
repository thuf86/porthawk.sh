<p align="center">
  <code>==================================== P O R T H A W K ====================================</code> <br>
  <b><i>Professional Port Scanner & Service Fingerprinting Engine</i></b> <br>
  <img src="https://img.shields.io/badge/Version-2.1-green?style=for-the-badge&logo=github">
  <img src="https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
  <img src="https://img.shields.io/badge/Authorized-Pentest-red?style=for-the-badge">
</p>

---

## 🦅 1. Visão Geral
O **PortHawk** é um scanner de portas TCP de alto desempenho, projetado para ser robusto, moderno e eficaz. Ele combina uma interface interativa amigável com um backend potente que utiliza concorrência (threading) e **fingerprinting** para identificar não apenas portas abertas, mas as assinaturas reais dos serviços (banners).

<p align="center">
  <img width="850" alt="PortHawk Dashboard" src="https://github.com/user-attachments/assets/98adc807-6aa8-4c3f-92ff-e4a9f3d6ff7a" />
</p>

## 🛠️ 2. Instalação e Requisitos

### Pré-requisitos
- **SO:** Linux (Kali/Ubuntu), Windows ou macOS
- **Python:** Versão 3.7 ou superior instalado

### Configuração
Clone o repositório e instale as dependências necessárias via terminal:
```bash
pip install pyfiglet tqdm colorama
