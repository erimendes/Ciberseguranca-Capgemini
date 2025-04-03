import json
import streamlit as st
from datetime import datetime

class NotificationSystem:
    """Classe para envio de notificações e alertas de segurança"""
    
    def __init__(self, config):
        self.config = config
        self.offline_mode = True
        # Inicializar lista de notificações na sessão
        if "notifications" not in st.session_state:
            st.session_state.notifications = []
    
    def send_telegram_alert(self, message):
        """Simula o envio de alerta via Telegram"""
        # Apenas simular sem fazer requisições reais
        return True
    
    def send_discord_alert(self, message):
        """Simula o envio de alerta via webhook do Discord"""
        # Apenas simular sem fazer requisições reais
        return True
    
    def notify_threat(self, ip, threat_data):
        """Simula o envio de notificação para canais configurados"""
        # Apenas criar a mensagem sem enviar
        message = f"""🚨 ALERTA 🚨
IP: {ip}
Nível: {threat_data['level']}
Detalhes: {', '.join(threat_data.get('details', []))}"""
        
        # Simular envio bem-sucedido
        return {
            "telegram": True,
            "discord": True,
            "success": True
        }
    
    def send_notification(self, message, priority="normal"):
        """Envia uma notificação com prioridade especificada
        
        Args:
            message (str): Mensagem de notificação
            priority (str): Prioridade da notificação ('alta', 'média', 'normal')
        """
        try:
            # Criação do objeto de notificação
            notification = {
                "message": message,
                "priority": priority,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "read": False
            }
            
            # Adicionar à lista de notificações na sessão
            st.session_state.notifications.append(notification)
            
            # Registrar no console (simulação)
            print(f"NOTIFICAÇÃO [{priority.upper()}]: {message}")
            
            return True
        except Exception as e:
            print(f"Erro ao enviar notificação: {str(e)}")
            return False
            
    def get_notifications(self, limit=10, only_unread=False):
        """Retorna as notificações mais recentes
        
        Args:
            limit (int): Número máximo de notificações a retornar
            only_unread (bool): Se True, retorna apenas notificações não lidas
            
        Returns:
            list: Lista de notificações
        """
        if "notifications" not in st.session_state:
            return []
            
        notifications = st.session_state.notifications
        
        if only_unread:
            notifications = [n for n in notifications if not n["read"]]
            
        # Ordenar por timestamp (mais recentes primeiro) e limitar
        return sorted(notifications, 
                     key=lambda x: x["timestamp"], 
                     reverse=True)[:limit]
    
    def mark_as_read(self, index):
        """Marca uma notificação como lida
        
        Args:
            index (int): Índice da notificação a ser marcada
        """
        if (0 <= index < len(st.session_state.notifications)):
            st.session_state.notifications[index]["read"] = True 