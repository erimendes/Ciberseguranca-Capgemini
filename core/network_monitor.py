import random
import time
from datetime import datetime
import streamlit as st

class NetworkMonitor:
    """Classe simplificada para monitoramento de rede e detecção de ameaças"""
    
    def __init__(self, config, logger, security_agent):
        self.config = config
        self.logger = logger
        self.security_agent = security_agent
    
    def start_monitoring(self):
        """Inicia um ciclo de monitoramento da rede"""
        try:
            self.logger.log_activity("Iniciando ciclo de monitoramento da rede", 'info')
            
            # Contador de ciclos
            if "monitoring_cycles" not in st.session_state:
                st.session_state.monitoring_cycles = 0
            st.session_state.monitoring_cycles += 1
            
            # Simular eventos de rede (3-5 eventos)
            num_events = random.randint(3, 5)
            
            # Log de início de ciclo
            self.logger.log_activity(f"Ciclo de monitoramento #{st.session_state.monitoring_cycles}: Iniciado com {num_events} eventos", 'info')
            
            # Simular eventos
            for i in range(num_events):
                # 80% de chance de tráfego normal
                if random.random() < 0.8:
                    self._log_normal_traffic()
                else:
                    # Log de tráfego suspeito
                    ip = self._generate_random_ip()
                    self.logger.log_activity(f"Tráfego suspeito detectado de {ip}", 'warning')
            
            # Log de conclusão
            self.logger.log_activity(f"Ciclo de monitoramento #{st.session_state.monitoring_cycles}: Concluído", 'success')
            return True
            
        except Exception as e:
            self.logger.log_activity(f"Erro ao monitorar rede: {str(e)}", 'error')
            return False

    def generate_test_traffic(self):
        """Gera tráfego de rede de teste"""
        try:
            self.logger.log_activity("Gerando tráfego de teste", 'info')
            
            # Gerar um IP de alto risco
            ip = "192.168.1." + str(random.randint(1, 254))
            
            # Registrar
            self.logger.log_activity(f"Tráfego malicioso detectado de {ip}", 'error')
            
            # Criar dados de ameaça
            threat_data = {
                "ip": ip,
                "type": "Ataque simulado pelo usuário",
                "details": "Tráfego malicioso de teste",
                "timestamp": datetime.now().isoformat(),
                "risk_level": "high"
            }
            
            # Analisar a ameaça
            self.security_agent.analyze_threat(threat_data)
            return True
            
        except Exception as e:
            self.logger.log_activity(f"Erro ao gerar tráfego de teste: {str(e)}", 'error')
            return False
    
    def _log_normal_traffic(self):
        """Gera log de tráfego normal"""
        services = ["Web", "Email", "DNS", "FTP", "Database", "API"]
        service = random.choice(services)
        ip = self._generate_random_ip()
        action = random.choice(["acesso", "solicitação", "conexão"])
        
        self.logger.log_activity(f"Tráfego normal: {service} {action} de {ip}", 'info')
    
    def _generate_random_ip(self):
        """Gera um endereço IP aleatório"""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" 