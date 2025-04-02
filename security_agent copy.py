import os
import json
import streamlit as st
from datetime import datetime
from typing import Dict
import time
import threading
import random
import subprocess
import platform

class SecurityAgent:
    """Classe principal de agente de segurança que coordena ações de defesa."""
    
    def __init__(self, config, logger, threat_intel, notification_system):
        self.config = config
        self.logger = logger
        self.threat_intel = threat_intel
        self.notification_system = notification_system
        
        # Inicialização das variáveis de sessão
        self._initialize_session_state()

        self.honeypot_ip = "192.168.1.250"
        self.honeypot_port = 8888
        self._last_analysis_time = 0
        self._analysis_lock = threading.Lock()

    def _initialize_session_state(self):
        """Inicializa os conjuntos de IPs e estatísticas na sessão do Streamlit."""
        if "blocked_ips" not in st.session_state:
            st.session_state.blocked_ips = set()
        if "monitored_ips" not in st.session_state:
            st.session_state.monitored_ips = set()
        if "honeypot_ips" not in st.session_state:
            st.session_state.honeypot_ips = set()
        if "threat_stats" not in st.session_state:
            st.session_state.threat_stats = {"high": 0, "medium": 0, "low": 0}

    def analyze_threat(self, threat_data: Dict[str, str]) -> str:
        """Analisa uma ameaça detectada e toma ações apropriadas."""
        try:
            threat_ip = threat_data.get("ip", "desconhecido")

            # Verifica se o IP já foi tratado (bloqueado ou monitorado)
            if threat_ip in st.session_state.blocked_ips:
                self.logger.log_activity(f"IP {threat_ip} já está bloqueado. Ignorando nova ameaça.", "warning")
                return

            if threat_ip in st.session_state.monitored_ips:
                self.logger.log_activity(f"IP {threat_ip} já está em monitoramento.", "warning")

            self.logger.log_activity(f"⚠️ Analisando ameaça do IP: {threat_ip}", "warning")
            time.sleep(0.5)  # Simulando processamento

            risk_level = threat_data.get("risk_level", self._classify_threat(threat_data))
            self._update_threat_stats(risk_level)

            # Ações conforme o nível de risco
            return self._handle_threat_action(risk_level, threat_ip)
        
        except Exception as e:
            self.logger.log_activity(f"Erro ao analisar ameaça: {str(e)}", "error")
            return None

    def _update_threat_stats(self, risk_level: str):
        """Atualiza as estatísticas de ameaças com o nível de risco."""
        if risk_level in st.session_state.threat_stats:
            st.session_state.threat_stats[risk_level] += 1

    def _handle_threat_action(self, risk_level: str, threat_ip: str) -> str:
        """Define as ações baseadas no nível de risco da ameaça."""
        if risk_level == "high":
            return self._handle_high_risk(threat_ip)
        elif risk_level == "medium":
            return self.monitor_ip(threat_ip)
        else:
            self.logger.log_activity(f"🔒 Análise concluída. Nível de ameaça: BAIXO", "info")
            return "BAIXO"

    def _handle_high_risk(self, threat_ip: str) -> str:
        """Lida com ameaças de alto risco (bloqueio ou redirecionamento para honeypot)."""
        if random.random() < 0.5:
            self.redirect_to_honeypot(threat_ip)
            self.logger.log_activity(f"🍯 IP {threat_ip} redirecionado para honeypot", "error")
            return "ALTO - Redirecionado para honeypot"
        else:
            self.block_ip(threat_ip)
            self.logger.log_activity(f"🔒 IP {threat_ip} bloqueado", "error")
            return "ALTO - Bloqueado"

    def monitor_ip(self, ip: str) -> str:
        """Adiciona um IP ao monitoramento contínuo."""
        if ip in st.session_state.monitored_ips:
            self.logger.log_activity(f"IP {ip} já está em monitoramento", "info")
            return "já está em monitoramento"
        
        st.session_state.monitored_ips.add(ip)
        self.logger.log_activity(f"IP {ip} adicionado ao monitoramento contínuo", "warning")
        return "colocado em monitoramento"

    def _classify_threat(self, threat_data: Dict) -> str:
        """Classifica o nível de ameaça com base nos dados recebidos."""
        return random.choice(["high", "medium", "low"])

    def block_ip(self, ip: str) -> str:
        """Bloqueia um IP na lista negra e registra a ação no sistema."""
        if ip in st.session_state.blocked_ips:
            self.logger.log_activity(f"IP {ip} já está bloqueado", 'info')
            return "já está bloqueado"
        
        st.session_state.blocked_ips.add(ip)
        self.logger.log_activity(f"🛡️ Bloqueando IP malicioso: {ip}", 'success')

        success = self._real_ip_block(ip)
        return "bloqueado com sucesso" if success else "registrado apenas no sistema"

    def _real_ip_block(self, ip: str) -> bool:
        """Implementa o bloqueio real do IP no sistema operacional."""
        try:
            system = platform.system().lower()
            if system == "windows":
                return self._block_ip_windows(ip)
            elif system == "linux":
                return self._block_ip_linux(ip)
            else:
                self.logger.log_activity(f"Sistema {system} não suportado para bloqueio", 'error')
                return False
        except Exception as e:
            self.logger.log_activity(f"Erro ao bloquear IP {ip}: {str(e)}", 'error')
            return False

    def _block_ip_windows(self, ip: str) -> bool:
        """Bloqueio do IP no Windows usando o Firewall."""
        rule_name = f"BlockIP-{ip.replace('.', '-')}"

        try:
            subprocess.run(f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}', shell=True)
            subprocess.run(f'netsh advfirewall firewall add rule name="{rule_name}-out" dir=out action=block remoteip={ip}', shell=True)
            return True
        except subprocess.CalledProcessError:
            self.logger.log_activity(f"Erro ao criar regra para IP {ip} no firewall", "error")
            return False

    def _block_ip_linux(self, ip: str) -> bool:
        """Bloqueio do IP no Linux usando iptables."""
        try:
            subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            subprocess.run(f"sudo iptables -A OUTPUT -d {ip} -j DROP", shell=True, check=True)
            return True
        except subprocess.CalledProcessError:
            self.logger.log_activity(f"Erro ao bloquear IP {ip} com iptables", "error")
            return False

    def redirect_to_honeypot(self, ip: str):
        """Redireciona um IP para o honeypot."""
        if ip in st.session_state.honeypot_ips:
            self.logger.log_activity(f"IP {ip} já está redirecionado para honeypot", 'info')
            return

        st.session_state.honeypot_ips.add(ip)
        self.logger.log_activity(f"🍯 Redirecionando IP {ip} para honeypot", 'success')

        # Simulação do redirecionamento
        self._real_honeypot_redirect(ip)

    def _real_honeypot_redirect(self, ip: str):
        """Simula o redirecionamento de tráfego de um IP para o honeypot."""
        system = platform.system().lower()
        if system == "windows":
            self.logger.log_activity(f"Comando simulado para redirecionamento de IP {ip} para honeypot", "info")
        elif system == "linux":
            self.logger.log_activity(f"Comando simulado para redirecionamento de IP {ip} para honeypot", "info")
        else:
            self.logger.log_activity(f"Redirecionamento para honeypot não implementado para {system}", "error")
