import streamlit as st
from datetime import datetime
import os
import sys

# Adicionar diretório atual ao path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

# Importar componentes do sistema
from config import Config
from logger import SecurityLogger
from network_monitor import NetworkMonitor
from security_agent import SecurityAgent
from threat_intelligence import ThreatIntelligence
from front import SecurityUI
from notification import NotificationSystem

def main():
    """Função principal para iniciar o sistema de segurança"""
    try:
        # Configurar estado da sessão
        if 'start_time' not in st.session_state:
            st.session_state.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state.monitoring_active = True
            print(f"Sistema inicializado em {st.session_state.start_time}")
            
        # Inicializar componentes
        config = Config()
        logger = SecurityLogger()
        
        # Log de inicialização do sistema
        logger.log_activity("Sistema inicializado com monitoramento autônomo ativo", 'success')

        # Inicializar agente, monitor e inteligência de ameaças
        threat_intel = ThreatIntelligence(config)
        notification_system = NotificationSystem(config)
        security_agent = SecurityAgent(config, logger, threat_intel, notification_system)
        network_monitor = NetworkMonitor(config, logger, security_agent)
        
        # Inicializar e executar a interface
        ui = SecurityUI(config, logger, network_monitor, security_agent, threat_intel)
        ui.run()

    except Exception as e:
        # Tratamento de erros
        st.error(f"Erro ao inicializar o sistema: {str(e)}")
        import traceback
        st.error(traceback.format_exc())
        print(f"Erro: {str(e)}")

if __name__ == "__main__":
    main()
