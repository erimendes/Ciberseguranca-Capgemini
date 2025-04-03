import os
import logging
from logging.handlers import RotatingFileHandler
import streamlit as st
from datetime import datetime

class SecurityLogger:
    """Classe para gerenciar logs do sistema de segurança"""
    
    def __init__(self):
        self.logger = self._setup_logging()
    
    def _setup_logging(self):
        """Configura o sistema de logs com rotação de arquivos"""
        try:
            # Criar diretório de logs no diretório atual
            log_dir = os.path.join(os.getcwd(), "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "security_monitor.log")
            
            # Configurar o logger
            logger = logging.getLogger("SecurityMonitor")
            logger.setLevel(logging.INFO)
            
            # Handler para arquivo com rotação
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.INFO)
            
            # Formato do log
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            
            # Adicionar handler ao logger
            logger.addHandler(file_handler)
            
            return logger
        except Exception as e:
            print(f"Erro ao configurar logger: {str(e)}")
            # Retornar um logger básico em caso de erro
            logger = logging.getLogger("SecurityMonitor")
            logger.setLevel(logging.INFO)
            return logger
    
    def log_activity(self, message, level='info'):
        """Registra atividade tanto na interface quanto no arquivo de log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {'timestamp': timestamp, 'message': message, 'level': level}
        
        # Registrar no arquivo de log
        try:
            if level == 'error':
                self.logger.error(message)
            elif level == 'success':
                self.logger.info(f"SUCCESS: {message}")
            else:
                self.logger.info(message)
        except Exception as e:
            print(f"Erro ao registrar log no arquivo: {str(e)}")
        
        # Registrar na interface Streamlit
        try:
            # Garantir que activity_log exista no session_state
            if "activity_log" not in st.session_state:
                st.session_state.activity_log = []
                
            st.session_state.activity_log.append(log_entry)
            
            if len(st.session_state.activity_log) > 100:
                st.session_state.activity_log = st.session_state.activity_log[-100:]
        except Exception as e:
            print(f"Erro ao registrar log na interface: {str(e)}")
    
    def get_recent_logs(self, count=10):
        """Retorna os logs mais recentes"""
        if "activity_log" in st.session_state and st.session_state.activity_log:
            return st.session_state.activity_log[-count:]
        return []
    
    def get_all_logs(self):
        """Tenta ler o arquivo de log completo"""
        try:
            log_file = os.path.join(os.getcwd(), "logs", "security_monitor.log")
            if os.path.exists(log_file):
                with open(log_file, "r", encoding='utf-8') as f:
                    return f.read()
            return "Nenhum log encontrado."
        except Exception as e:
            self.log_activity(f"Erro ao ler arquivo de logs: {str(e)}", 'error')
            return f"Erro ao ler logs: {str(e)}" 