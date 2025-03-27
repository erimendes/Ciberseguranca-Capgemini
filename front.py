import streamlit as st
import pandas as pd
import plotly.express as px
import time
from datetime import datetime
import random
import platform
import subprocess

class SecurityUI:
    """Classe para gerenciar a interface do usuário do sistema de segurança"""
    
    def __init__(self, config, logger, network_monitor, security_agent, threat_intel):
        self.config = config
        self.logger = logger
        self.network_monitor = network_monitor
        self.security_agent = security_agent
        self.threat_intel = threat_intel
    
    def run(self):
        """Iniciar a interface Streamlit"""
        # Configurações da página
        st.set_page_config(page_title="Agente Autônomo de Segurança", layout="wide")
        
        # Inicializar estado da sessão
        self._initialize_session_state()
        
        # Simulação automática de ataques
        self._auto_simulate_attack()
        
        # Renderizar componentes da UI
        self._render_header()
        self._render_metrics()
        self._render_controls()
        self._render_logs()
        self._render_sidebar()
        self._render_threat_intelligence()
        
        # Atualização automática a cada 5 segundos
        time.sleep(5)  # Esperar 5 segundos
        st.rerun()  # Atualizar a página automaticamente
    
    def _initialize_session_state(self):
        """Inicializa todos os estados da sessão diretamente"""
        if "blocked_ips" not in st.session_state:
            st.session_state.blocked_ips = set()
        if "threat_stats" not in st.session_state:
            st.session_state.threat_stats = {'high': 0, 'medium': 0, 'low': 0}
        if "activity_log" not in st.session_state:
            st.session_state.activity_log = []
        if "monitoring_active" not in st.session_state:
            st.session_state.monitoring_active = True
        if "monitoring_cycles" not in st.session_state:
            st.session_state.monitoring_cycles = 0
        if "last_attack_time" not in st.session_state:
            st.session_state.last_attack_time = 0
    
    def _auto_simulate_attack(self):
        """Simulação automática de ataques"""
        current_time = time.time()
        
        # Verificar se é o primeiro carregamento da página
        first_load = False
        if "last_page_load" not in st.session_state:
            st.session_state.last_page_load = current_time
            first_load = True
            
        # Simular ataques em sequência no primeiro carregamento
        if first_load:
            # Gerar 3 ataques iniciais (1 de cada tipo)
            self._simulate_attack_by_level("high")
            self._simulate_attack_by_level("medium")
            self._simulate_attack_by_level("low")
            st.session_state.last_attack_time = current_time
            
        # Realizar ciclo de monitoramento a cada 10 segundos
        if "last_monitoring_time" not in st.session_state:
            st.session_state.last_monitoring_time = 0
            
        if current_time - st.session_state.last_monitoring_time >= 10:
            self.network_monitor.start_monitoring()
            st.session_state.last_monitoring_time = current_time
        
        # Simular um ataque a cada 7 segundos
        if current_time - st.session_state.last_attack_time >= 7:
            self._simulate_random_attack()
            st.session_state.last_attack_time = current_time
            
    def _simulate_attack_by_level(self, risk_level):
        """Simula um ataque de nível específico (alto, médio ou baixo)"""
        # Lista de IPs por categoria de risco
        high_risk_ips = [
            "192.168.1." + str(random.randint(1, 254)),
            "10.0.0." + str(random.randint(1, 254)),
            "172.16.0." + str(random.randint(1, 254))
        ]
        
        medium_risk_ips = [
            "8.8.8." + str(random.randint(1, 254)),
            "1.1.1." + str(random.randint(1, 254)),
            "208.67.222." + str(random.randint(1, 254))
        ]
        
        low_risk_ips = [
            "216.58.215." + str(random.randint(1, 254)),
            "151.101." + str(random.randint(1, 254)),
            "13.32." + str(random.randint(1, 254))
        ]
        
        # Configurar com base no nível solicitado
        if risk_level == "high":
            selected_ip = random.choice(high_risk_ips)
            risk_text = "ALTO"
            log_type = 'error'
            threat_types = ["Tentativa de Acesso Não Autorizado", "Execução de Código Remoto", "Ataque de Força Bruta"]
            threat_details = ["Padrão de ataque conhecido detectado", "Tráfego malicioso detectado"]
        elif risk_level == "medium":
            selected_ip = random.choice(medium_risk_ips)
            risk_text = "MÉDIO"
            log_type = 'warning'
            threat_types = ["Atividade de Rede Suspeita", "Transferência Incomum de Dados", "Conexão Suspeita"]
            threat_details = ["Padrão de tráfego incomum", "Tráfego suspeito detectado"]
        else:  # baixo
            selected_ip = random.choice(low_risk_ips)
            risk_text = "BAIXO"
            log_type = 'info'
            threat_types = ["Atividade Incomum", "Acesso a Recursos Sensíveis", "Comportamento Fora de Padrão"]
            threat_details = ["Possível falso positivo", "Comportamento incomum detectado"]
        
        # Seleciona protocolos e portas
        protocol = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS"])
        port = random.randint(1, 65535)
        
        # Registra o alerta
        log_message = f"⚠️ ATAQUE SIMULADO: {random.choice(threat_types)} de {selected_ip}:{port} via {protocol} - Risco {risk_text}"
        self.logger.log_activity(log_message, log_type)
        
        # Envia para análise no security agent
        threat_data = {
            "ip": selected_ip,
            "type": random.choice(threat_types),
            "details": random.choice(threat_details),
            "timestamp": datetime.now().isoformat(),
            "risk_level": risk_level
        }
        
        # Analisar a ameaça
        self.security_agent.analyze_threat(threat_data)
    
    def _render_header(self):
        """Renderiza o cabeçalho da aplicação"""
        st.title("🤖 Agente Autônomo de Segurança Cibernética")
        st.markdown("### 🔄 Sistema Autônomo Ativo - Ataques Simulados a cada 7 segundos")
        
        # Informação sobre atualização automática
        st.success("✅ Sistema completamente autônomo: simula ataques a cada 7 segundos e atualiza os logs automaticamente a cada 5 segundos.")
        
        # Esconder botões de simulação manual já que agora é automático
        if st.checkbox("📊 Mostrar Controles Manuais", value=False):
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Forçar Ciclo de Monitoramento", use_container_width=True):
                    self.network_monitor.start_monitoring()
            
            with col2:
                if st.button("⚠️ Forçar Detecção de Ameaça", use_container_width=True):
                    self._simulate_random_attack()
    
    def _render_metrics(self):
        """Renderiza métricas principais"""
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("IPs Bloqueados", len(st.session_state.blocked_ips))
        col2.metric("IPs em Monitoramento", len(st.session_state.get("monitored_ips", set())))
        col3.metric("IPs em Honeypot", len(st.session_state.get("honeypot_ips", set())))
        col4.metric("Ciclos de Monitoramento", st.session_state.get("monitoring_cycles", 0))
        
        # Adicionar gráfico opcional se houver dados suficientes
        if st.session_state.threat_stats["high"] > 0 or st.session_state.threat_stats["medium"] > 0 or st.session_state.threat_stats["low"] > 0:
            data = {
                "Tipo": ["Alto", "Médio", "Baixo"],
                "Quantidade": [
                    st.session_state.threat_stats["high"],
                    st.session_state.threat_stats["medium"],
                    st.session_state.threat_stats["low"]
                ]
            }
            df = pd.DataFrame(data)
            fig = px.pie(df, values="Quantidade", names="Tipo", title="Distribuição de Ameaças")
            st.plotly_chart(fig, use_container_width=True)
    
    def _render_controls(self):
        """Renderiza controles simplificados"""
        with st.container():
            st.subheader("📊 Monitoramento de Rede")
            
            # Status de monitoramento automático
            st.success("✅ Sistema de Monitoramento Ativo")
            
            # Seção para verificar bloqueio real
            st.subheader("🔍 Verificação de Bloqueio Real")
            with st.expander("Verificar se um IP está bloqueado no firewall"):
                if "blocked_ips" in st.session_state and len(st.session_state.blocked_ips) > 0:
                    st.write("#### IPs atualmente bloqueados no sistema:")
                    blocked_list = list(st.session_state.blocked_ips)
                    
                    for ip in blocked_list:
                        col1, col2 = st.columns([4, 1])
                        with col1:
                            st.write(f"🛑 **{ip}**")
                        with col2:
                            if st.button(f"Verificar", key=f"check_{ip}"):
                                is_blocked = self._check_ip_blocked(ip)
                                if is_blocked:
                                    st.success(f"✅ O IP {ip} está realmente bloqueado no firewall")
                                else:
                                    st.error(f"❌ O IP {ip} NÃO está bloqueado no firewall")
                else:
                    st.info("Nenhum IP foi bloqueado ainda.")
                    
                st.write("---")
                st.write("Teste o bloqueio tentando pingar o IP:")
                st.code("ping 192.168.1.100")
                st.write("Se o IP estiver bloqueado, você verá erros de timeout ou falha na conexão.")
    
    def _check_ip_blocked(self, ip):
        """Verifica se um IP está realmente bloqueado no firewall
        
        Args:
            ip (str): O IP a verificar
            
        Returns:
            bool: True se estiver bloqueado, False caso contrário
        """
        try:
            system = platform.system().lower()
            
            if system == "windows":
                rule_name = f"BlockIP-{ip.replace('.', '-')}"
                check_command = f'netsh advfirewall firewall show rule name="{rule_name}"'
                result = subprocess.run(check_command, shell=True, capture_output=True, text=True)
                
                return "No rules match the specified criteria" not in result.stdout
                
            elif system == "linux":
                check_command = f"sudo iptables -C INPUT -s {ip} -j DROP"
                result = subprocess.run(check_command, shell=True, capture_output=True)
                
                return result.returncode == 0
                
            else:
                return False
                
        except Exception as e:
            self.logger.log_activity(f"Erro ao verificar bloqueio do IP {ip}: {str(e)}", 'error')
            return False
    
    def _simulate_random_attack(self):
        """Simula um ataque com nível de risco variado com chances iguais"""
        # Decidir o nível de risco (33% para cada)
        risk_chance = random.random()
        
        # Lista de IPs por categoria de risco
        high_risk_ips = [
            "192.168.1." + str(random.randint(1, 254)),
            "10.0.0." + str(random.randint(1, 254)),
            "172.16.0." + str(random.randint(1, 254)),
            "45.33." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "104.131." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "185.25." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        ]
        
        medium_risk_ips = [
            "8.8.8." + str(random.randint(1, 254)),
            "1.1.1." + str(random.randint(1, 254)),
            "208.67.222." + str(random.randint(1, 254)),
            "195.12." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        ]
        
        low_risk_ips = [
            "216.58.215." + str(random.randint(1, 254)),
            "151.101." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254)),
            "13.32." + str(random.randint(1, 254)) + "." + str(random.randint(1, 254))
        ]
        
        # Selecionar nível de risco e IP correspondente (33% cada)
        if risk_chance < 0.33:  # 33% chance alta
            risk_level = "high"
            selected_ip = random.choice(high_risk_ips)
            risk_text = "ALTO"
            log_type = 'error'
            threat_types = [
                "Tentativa de Acesso Não Autorizado",
                "Injeção de SQL",
                "Execução de Código Remoto",
                "Ataque de Força Bruta",
                "Propagação de Malware",
                "Comunicação com Servidor C&C",
                "Varredura de Vulnerabilidades"
            ]
            threat_details = [
                "Padrão de ataque conhecido detectado",
                "Múltiplas tentativas de autenticação falhas",
                "Tráfego malicioso detectado",
                "Assinatura de exploit conhecida",
                "Comportamento consistente com roubo de dados"
            ]
        elif risk_chance < 0.66:  # 33% chance média
            risk_level = "medium"
            selected_ip = random.choice(medium_risk_ips)
            risk_text = "MÉDIO"
            log_type = 'warning'
            threat_types = [
                "Atividade de Rede Suspeita",
                "Comportamento Anômalo de Usuário",
                "Transferência Incomum de Dados",
                "Conexão Suspeita",
                "Tentativa de Acesso a Recurso Restrito"
            ]
            threat_details = [
                "Padrão de tráfego incomum",
                "Comunicação com domínio recentemente registrado",
                "Tráfego suspeito detectado",
                "Volume de dados anormal"
            ]
        else:  # 33% chance baixa
            risk_level = "low"
            selected_ip = random.choice(low_risk_ips)
            risk_text = "BAIXO"
            log_type = 'info'
            threat_types = [
                "Atividade Incomum",
                "Tentativa de Login de Nova Localização",
                "Acesso a Recursos Sensíveis",
                "Comportamento Fora de Padrão",
                "Alteração de Configuração"
            ]
            threat_details = [
                "Possível falso positivo",
                "Comportamento incomum detectado",
                "Pequeno desvio de comportamento padrão"
            ]
        
        # Seleciona protocolos e portas
        protocol = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SMB", "RDP", "SSH"])
        port = random.randint(1, 65535)
        
        # Registra o alerta
        log_message = f"⚠️ ATAQUE SIMULADO: {random.choice(threat_types)} de {selected_ip}:{port} via {protocol} - Risco {risk_text}"
        self.logger.log_activity(log_message, log_type)
        
        # Envia para análise no security agent
        threat_data = {
            "ip": selected_ip,
            "type": random.choice(threat_types),
            "details": random.choice(threat_details),
            "timestamp": datetime.now().isoformat(),
            "risk_level": risk_level
        }
        
        # Analisar a ameaça
        self.security_agent.analyze_threat(threat_data)
    
    def _render_logs(self):
        """Renderiza seção de logs"""
        st.subheader("📝 Logs em Tempo Real")
        log_container = st.empty()
        
        # Mostrar logs recentes
        logs = self.logger.get_recent_logs(30)
        log_text = "\n".join([f"{log['timestamp']} - {log['message']}" for log in logs])
        log_container.text_area("Últimos 30 logs", log_text, height=400)
    
    def _render_sidebar(self):
        """Renderiza a barra lateral com informações essenciais"""
        st.sidebar.title("Sistema Autônomo Ativo")
        
        # Status do sistema
        if st.session_state.get('monitoring_active', False):
            st.sidebar.success("Sistema de Monitoramento Ativo")
        else:
            st.sidebar.warning("Sistema de Monitoramento Inativo")
        
        # Lista de IPs Monitorados
        if st.session_state.get('monitored_ips'):
            st.sidebar.subheader("IPs Monitorados")
            for ip in st.session_state.monitored_ips:
                st.sidebar.text(f"• {ip}")
        
        # Lista de IPs em Honeypot
        if st.session_state.get('honeypot_ips'):
            st.sidebar.subheader("IPs em Honeypot 🍯")
            for ip in st.session_state.honeypot_ips:
                st.sidebar.text(f"• {ip}")
        
        # Lista de IPs Bloqueados
        if st.session_state.get('blocked_ips'):
            st.sidebar.subheader("IPs Bloqueados")
            for ip in st.session_state.blocked_ips:
                st.sidebar.text(f"• {ip}")
    
    def _render_threat_intelligence(self):
        """Renderiza seção de inteligência de ameaças"""
        st.subheader("🔍 Inteligência de Ameaças")
        
        # Campo de busca de IP
        ip_to_check = st.text_input("Buscar informações de IP")
        if ip_to_check and st.button("Pesquisar"):
            self._display_threat_intelligence(ip_to_check)
    
    def _display_threat_intelligence(self, ip):
        """Exibe informações de inteligência de ameaças na interface"""
        st.info("⏳ Analisando IP... O agente está pensando.")
        
        # Verificar se o sistema está usando LLM ou regras offline
        is_using_llm = not self.threat_intel.offline_mode and self.threat_intel.llm is not None
        
        # Obter dados das "APIs" (simuladas ou reais)
        vt_data = self.threat_intel.check_virustotal(ip)
        abuse_data = self.threat_intel.check_abuseipdb(ip)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**VirusTotal**")
            if "error" not in vt_data:
                st.metric("Detecções Maliciosas", vt_data["malicious"])
                st.metric("Detecções Suspeitas", vt_data["suspicious"])
                st.metric("Detecções Inofensivas", vt_data["harmless"])
            else:
                st.error(vt_data["error"])
        
        with col2:
            st.write("**AbuseIPDB**")
            if "error" not in abuse_data:
                st.metric("Score de Confiança", f"{abuse_data['abuse_confidence_score']}%")
                st.metric("Total de Relatórios", abuse_data["total_reports"])
                if abuse_data["last_reported_at"]:
                    st.write(f"Último relatório: {abuse_data['last_reported_at']}")
            else:
                st.error(abuse_data["error"])
        
        # Análise de ameaça
        if "error" not in vt_data and "error" not in abuse_data:
            threat_intel = self.threat_intel.analyze_threat_intelligence(ip)
            
            # Mostrar emblema LLM se estiver usando modelo
            risk_level_text = threat_intel['level']
            if is_using_llm:
                st.subheader(f"Análise de Ameaça: {risk_level_text} 🤖")
                st.info("Análise aprimorada por IA usando modelo de linguagem")
            else:
                st.subheader(f"Análise de Ameaça: {risk_level_text}")
            
            # Barra de progresso com cor baseada no risco
            risk_color = "red" if risk_level_text == "ALTO" else "orange" if risk_level_text == "MÉDIO" else "green"
            st.markdown(
                f"""
                <div style="background-color: #1E1E1E; border-radius: 10px; padding: 10px;">
                    <div style="background-color: {risk_color}; width: {min(threat_intel['score'] * 10, 100)}%; 
                    height: 20px; border-radius: 5px;"></div>
                </div>
                """, 
                unsafe_allow_html=True
            )
            
            if threat_intel["details"]:
                st.write("**Detalhes:**")
                for detail in threat_intel["details"]:
                    st.write(f"- {detail}")
            
            # Botão para bloquear IP
            if st.button(f"Bloquear IP {ip}"):
                result = self.security_agent.block_ip(ip)
                st.write(f"IP {ip} {result}") 