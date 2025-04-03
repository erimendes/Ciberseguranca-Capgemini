import os
import json
import streamlit as st
from datetime import datetime
from typing import Dict, List, Union, Any
import time
import threading
import random
import subprocess
import platform
import shlex  # For safe command execution on Linux/macOS
import re  # For better IP validation
from collections.abc import Mapping  # For abstract base class

class SecurityAgent:
    """A classe que implementa um agente de segurança."""

    def __init__(self, config: Mapping, logger, threat_intel, notification_system):
        """Inicializa o Agente de Segurança."""

        self.config = config
        self.logger = logger
        self.threat_intel = threat_intel
        self.notification_system = notification_system

        # Inicializa session state (Streamlit specific)
        if "blocked_ips" not in st.session_state:
            st.session_state.blocked_ips = set()
        if "monitored_ips" not in st.session_state:
            st.session_state.monitored_ips = set()
        if "honeypot_ips" not in st.session_state:
            st.session_state.honeypot_ips = set()
        if "threat_stats" not in st.session_state:
            st.session_state.threat_stats = {"high": 0, "medium": 0, "low": 0}

        # Honeypot configuration
        self.honeypot_ip = self._get_config_value("honeypot_ip", "192.168.1.250")
        self.honeypot_port = self._get_config_value("honeypot_port", 8888)

        self._last_analysis_time = 0
        self._analysis_lock = threading.Lock()

    def _get_config_value(self, key: str, default: Any) -> Any:
        """Obtém um valor de configuração, tratando diferentes tipos de config."""

        if isinstance(self.config, Mapping):
            return self.config.get(key, default)
        elif hasattr(self.config, key):
            return getattr(self.config, key)
        else:
            self.logger.log_activity(f"Configuração '{key}' não encontrada, usando padrão: {default}", "warning")
            return default

    def _is_valid_ip(self, ip: str) -> bool:
        """Valida se a string fornecida é um endereço IPv4 válido."""

        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        octets = ip.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False
        return True

    def _execute_command(self, command: Union[str, List[str]], shell: bool = False, check: bool = True, capture_output: bool = True, text: bool = True) -> subprocess.CompletedProcess:
        """Executa um comando do sistema e trata exceções."""
        try:
            if shell:
                return subprocess.run(command, shell=True, check=check, capture_output=capture_output, text=text)
            else:
                return subprocess.run(command, shell=False, check=check, capture_output=capture_output, text=text)
        except subprocess.CalledProcessError as e:
            self.logger.log_activity(f"Erro ao executar o comando: {e.stderr}", "error")
            raise  # Levanta a exceção para tratamento adicional
        except FileNotFoundError as e:
            self.logger.log_activity(f"Comando não encontrado: {e.filename}", "error")
            raise
        except Exception as e:
            self.logger.log_activity(f"Erro inesperado ao executar o comando: {str(e)}", "error")
            raise

    def analyze_threat(self, threat_data: Dict) -> str:
        """Analisa dados de ameaças e toma as ações apropriadas."""
        try:
            threat_ip = threat_data.get("ip")
            if not self._is_valid_ip(threat_ip):
                self.logger.log_activity(f"Endereço IP inválido: {threat_ip}", "error")
                return None  # Ou lançar uma exceção

            if threat_ip in st.session_state.blocked_ips:
                self.logger.log_activity(f"IP {threat_ip} já está bloqueado. Ignorando.", "warning")
                return None

            if threat_ip in st.session_state.monitored_ips:
                self.logger.log_activity(f"IP {threat_ip} já está em monitoramento. Atualizando dados.", "warning")

            self.logger.log_activity(f"Analisando ameaça de IP: {threat_ip}", "warning")
            time.sleep(0.5)  # Simular processamento

            risk_level = threat_data.get("risk_level", self._classify_threat(threat_data))
            if risk_level not in st.session_state.threat_stats:
                self.logger.log_activity(f"Nível de risco inválido: {risk_level}", "error")
                return None  # Ou lidar com isso de forma diferente
            st.session_state.threat_stats[risk_level] += 1

            if risk_level == "high":
                if random.random() < 0.5:
                    self.redirect_to_honeypot(threat_ip)
                    threat_level = "ALTO"
                    self.logger.log_activity(f"Ameaça ALTO - Redirecionada para honeypot", "error")
                    self.notification_system.send_notification(f"Alerta de Segurança: IP {threat_ip} para honeypot (alto risco)", "alta")
                else:
                    self.block_ip(threat_ip)
                    threat_level = "ALTO"
                    self.logger.log_activity(f"Ameaça ALTO - Bloqueado", "error")
                    self.notification_system.send_notification(f"Alerta de Segurança: IP {threat_ip} bloqueado (alto risco)", "alta")
            elif risk_level == "medium":
                self.monitor_ip(threat_ip)
                threat_level = "MÉDIO"
                self.logger.log_activity(f"Ameaça MÉDIO", "warning")
                self.logger.log_activity(f"IP {threat_ip} adicionado ao monitoramento contínuo", "warning")
                self.notification_system.send_notification(f"Alerta de Segurança: IP {threat_ip} monitorando (risco médio)", "média")
            else:
                threat_level = "BAIXO"
                self.logger.log_activity(f"Ameaça BAIXO", "info")

            return threat_level

        except Exception as e:
            self.logger.log_activity(f"Erro ao analisar a ameaça: {str(e)}", "error")
            return None

    # (Outros métodos como monitor_ip, _classify_threat, block_ip, etc.)
    # ... Veja outros exemplos abaixo para melhorias desses métodos

    def block_ip(self, ip: str) -> str:
        """Bloqueia um endereço IP malicioso."""

        if not self._is_valid_ip(ip):
            self.logger.log_activity(f"Endereço IP inválido: {ip}", "error")
            return "IP inválido"

        if ip in st.session_state.blocked_ips:
            self.logger.log_activity(f"IP {ip} já está bloqueado", "info")
            return "já bloqueado"

        self.logger.log_activity(f"Bloqueando IP malicioso: {ip}", "success")
        st.session_state.blocked_ips.add(ip)

        success = self._real_ip_block(ip)
        if success:
            self.logger.log_activity(f"IP {ip} bloqueado com sucesso no firewall", "success")
            return "bloqueado com sucesso"
        else:
            self.logger.log_activity(f"IP {ip} bloqueado no sistema, falha no firewall", "warning")
            return "bloqueado no sistema, falha no firewall"

    def _real_ip_block(self, ip: str) -> bool:
        """Implementa o bloqueio real do IP no sistema operacional."""
        try:
            system = platform.system().lower()
            if system == "windows":
                rule_name = f"BlockIP-{ip.replace('.', '-')}"
                self.logger.log_activity(f"Criando regra de bloqueio de entrada para IP {ip}", "info")
                inbound_command = ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + rule_name, "dir=in", "action=block", "remoteip=" + ip]  # LIST
                self._execute_command(inbound_command)

                self.logger.log_activity(f"Criando regra de bloqueio de saída para IP {ip}", "info")
                outbound_command = ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + rule_name + "-out", "dir=out", "action=block", "remoteip=" + ip]  # LIST
                self._execute_command(outbound_command)

                check_command = ["netsh", "advfirewall", "firewall", "show", "rule", "name=" + rule_name]  # LIST
                result = self._execute_command(check_command)
                return "Nenhuma regra correspondente aos critérios especificados" not in result.stdout

            elif system == "linux":
                self.logger.log_activity(f"Bloqueando {ip} em iptables", "info")
                inbound_command = ["sudo", "iptables", "-A", "INPUT", "-s", shlex.quote(ip), "-j", "DROP"]  # LIST + shlex
                self._execute_command(inbound_command)
                outbound_command = ["sudo", "iptables", "-A", "OUTPUT", "-d", shlex.quote(ip), "-j", "DROP"]  # LIST + shlex
                self._execute_command(outbound_command)
                return True

            else:
                self.logger.log_activity(f"SO {system} não suportado para bloqueio real", "error")
                return False

        except subprocess.CalledProcessError as e:
            self.logger.log_activity(f"Erro ao bloquear IP {ip} no firewall: {e.stderr}", "error")
            return False
        except Exception as e:
            self.logger.log_activity(f"Erro ao bloquear IP {ip}: {str(e)}", "error")
            return False

    def redirect_to_honeypot(self, ip: str) -> str:
        """Redireciona um IP malicioso para um honeypot."""

        if not self._is_valid_ip(ip):
            self.logger.log_activity(f"Endereço IP inválido: {ip}", "error")
            return "IP inválido"

        if ip in st.session_state.honeypot_ips:
            self.logger.log_activity(f"IP {ip} já redirecionado para o honeypot", "info")
            return "já redirecionado"

        self.logger.log_activity(f"Redirecionando IP malicioso para o honeypot: {ip}", "success")
        st.session_state.honeypot_ips.add(ip)

        success = self._real_honeypot_redirect(ip)
        if success:
            self.logger.log_activity(f"IP {ip} redirecionado com sucesso para o honeypot em {self.honeypot_ip}:{self.honeypot_port}", "success")
            return "redirecionado com sucesso"
        else:
            self.logger.log_activity(f"Redirecionamento do IP {ip} registrado, mas falha ao configurar", "warning")
            return "redirecionamento registrado, configuração falhou"

    def _real_honeypot_redirect(self, ip: str) -> bool:
        """Implementa o redirecionamento real do IP para o honeypot."""
        try:
            system = platform.system().lower()
            if system == "windows":
                rule_name = f"HoneypotRedirect-{ip.replace('.', '-')}"
                self.logger.log_activity(f"Configurando o encaminhamento de porta para o honeypot em {self.honeypot_ip}:{self.honeypot_port}", "info")
                command = ["netsh", "interface", "portproxy", "add", "v4tov4",
                           f"listenport=80", f"listenaddress={ip}",
                           f"connectport={self.honeypot_port}", f"connectaddress={self.honeypot_ip}"]
                self._execute_command(command)  # Lista de comando
                return True

            elif system == "linux":
                self.logger.log_activity(f"Redirecionando {ip} para honeypot usando iptables", "info")
                command = ["sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
                           "-s", shlex.quote(ip), "-j", "DNAT",
                           "--to-destination", f"{self.honeypot_ip}:{self.honeypot_port}"]
                self._execute_command(command)  # Lista de comando + shlex
                return True

            else:
                self.logger.log_activity(f"Redirecionamento de honeypot não implementado para {system}", "error")
                return False

        except subprocess.CalledProcessError as e:
            self.logger.log_activity(f"Erro ao redirecionar o IP {ip} para o honeypot: {e.stderr}", "error")
            return False

        except Exception as e:
            self.logger.log_activity(f"Erro ao configurar o redirecionamento de honeypot: {str(e)}", "error")
            return False

    def unblock_ip(self, ip: str) -> str:
        """Desbloqueia um endereço IP previamente bloqueado."""

        if not self._is_valid_ip(ip):
            self.logger.log_activity(f"Endereço IP inválido: {ip}", "error")
            return "IP inválido"

        if ip not in st.session_state.blocked_ips:
            self.logger.log_activity(f"IP {ip} não está bloqueado no momento", "info")
            return "não bloqueado"

        st.session_state.blocked_ips.remove(ip)
        success = self._real_ip_unblock(ip)
        if success:
            self.logger.log_activity(f"IP {ip} desbloqueado com sucesso", "success")
            return "desbloqueado com sucesso"
        else:
            self.logger.log_activity(f"IP {ip} removido do sistema, mas falha ao desbloquear no firewall", "warning")
            return "removido do sistema, falha ao desbloquear no firewall"

    def _real_ip_unblock(self, ip: str) -> bool:
        """Remove o bloqueio de IP no nível do sistema operacional."""
        try:
            system = platform.system().lower()
            if system == "windows":
                rule_name_in = f"BlockIP-{ip.replace('.', '-')}"
                rule_name_out = rule_name_in + "-out"
                delete_in_command = ["netsh", "advfirewall", "firewall", "delete", "rule", "name=" + rule_name_in]  # LIST
                delete_out_command = ["netsh", "advfirewall", "firewall", "delete", "rule", "name=" + rule_name_out]  # LIST
                self._execute_command(delete_in_command)
                self._execute_command(delete_out_command)
                return True

            elif system == "linux":
                unblock_in_command = ["sudo", "iptables", "-D", "INPUT", "-s", shlex.quote(ip), "-j", "DROP"]  # LIST + shlex
                unblock_out_command = ["sudo", "iptables", "-D", "OUTPUT", "-d", shlex.quote(ip), "-j", "DROP"]  # LIST + shlex
                self._execute_command(unblock_in_command, check=False)  # Pode não existir
                self._execute_command(unblock_out_command, check=False)
                return True

            else:
                self.logger.log_activity(f"SO {system} não suportado para desbloqueio real", "error")
                return False

        except subprocess.CalledProcessError as e:
            self.logger.log_activity(f"Erro ao desbloquear IP {ip} no firewall: {e.stderr}", "error")
            return False

        except Exception as e:
            self.logger.log_activity(f"Erro ao desbloquear IP {ip}: {str(e)}", "error")
            return False