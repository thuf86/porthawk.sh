<p align="center">
  <code>==================================== P O R T H A W K ====================================</code><br>
  <b><i>Professional Port Scanner & Service Fingerprinting Engine</i></b><br><br>
  <img src="https://img.shields.io/badge/Version-2.1-green?style=for-the-badge&logo=github">
  <img src="https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge">
  <img src="https://img.shields.io/badge/Use-Authorized%20Pentest-red?style=for-the-badge">
</p>

<img width="1671" height="760" alt="image" src="https://github.com/user-attachments/assets/2bdfebd2-f690-45f5-97a0-3db31914f2a3" />


# 🛡️ PortHawk

**PortHawk** é um scanner de portas TCP **profissional, moderno e orientado a desempenho**, desenvolvido para **pentesters**, **analistas de segurança**, **red teamers** e **estudantes avançados**.

Ele une uma **interface interativa elegante**, **modo CLI para automação**, **concorrência inteligente** e **relatórios estruturados**, entregando uma experiência comparável a ferramentas profissionais de mercado — com código limpo e extensível.

**Autor:** Romildo (thuf)  
🌐 **Website:** [https://medium.com/@romildothuf]
📦 **Versão:** 2.1  


## 📌 Visão Geral

Diferente de scanners básicos, o PortHawk foi projetado para **uso real em auditorias autorizadas**, focando em:

- Performance previsível
- Estabilidade em grandes ranges
- Feedback visual claro
- Automação e relatórios
- Experiência de uso profissional (UX de terminal)


## ✨ Principais Recursos

- 🔍 Scan TCP multithreaded de alta performance
- 🧠 Concorrência dinâmica (threads adaptativas)
- 🧭 Resolução automática de hostname (DNS)
- 🎛️ Interface **Interativa + CLI**
- 📊 Barra de progresso em tempo real (tqdm)
- 🎨 Logs coloridos (Colorama)
- 🗂️ Relatórios em **TXT e JSON**
- 🛑 Encerramento seguro (graceful shutdown – Ctrl+C)
- 📈 Estatísticas finais (tempo, taxa, portas abertas)


## ⚙️ Requisitos

- **Python 3.7 ou superior**
- Linux / WSL / macOS / Windows
- Permissão para executar scripts Python

## 📦 Instalação

```bash
1️⃣ Clonar o repositório
git clone https://github.com/seuusuario/porthawk.git
cd porthawk

2️⃣ Criar ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate

3️⃣ Atualizar o pip
pip install --upgrade pip
python3 -m pip install tqdm
python3 -m pip install colorama


5️⃣ Dar permissão de execução ao script
chmod +x port_scanner.py

6️⃣ Executar o PortHawk
python3 porthawk.py

