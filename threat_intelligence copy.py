import json
import requests
from langchain.prompts import PromptTemplate
from langchain_openai import OpenAI
from typing import Dict, List
import time
import streamlit as st

class ThreatIntelligence:
    """Classe para análise de inteligência de ameaças"""
    
    def __init__(self, config):
        self.config = config
        self.llm = self._initialize_llm()
        self.prompt = self._create_prompt()
        self.offline_mode = False  # Definindo como False para usar o LLM real agora que temos uma chave API válida
        self.session_state = st.session_state  # Acesso às variáveis de sessão do Streamlit
    
    def _initialize_llm(self) -> OpenAI:
        """Inicializa o modelo de linguagem para análise de ameaças"""
        try:
            return OpenAI(
                model="gpt-3.5-turbo-instruct",  # Modelo mais acessível e rápido
                temperature=0.1,
                max_tokens=512,
                api_key=self.config.openai_api_key
            )
        except Exception as e:
            print(f"Erro ao inicializar LLM: {str(e)}")
            return None
    
    def _create_prompt(self) -> PromptTemplate:
        """Cria o template de prompt para análise de ameaças"""
        return PromptTemplate(
            input_variables=["ip", "type", "details"],
            template="""Você é um especialista em segurança cibernética analisando uma possível ameaça.
            
            Analise os seguintes dados de segurança:
            IP: {ip}
            Tipo de Evento: {type}
            Detalhes: {details}
            
            Determine o nível de ameaça como ALTO, MÉDIO ou BAIXO com base nos padrões a seguir:
            
            - ALTO: IPs envolvidos em ataques de força bruta, execução remota de código, propagação de malware, comunicação com C&C, ou qualquer IP dos padrões 192.168.1.*, 10.0.0.*, 172.16.0.*, 45.33.*, 104.131.*, 185.25.*, 159.65.*
            - MÉDIO: IPs envolvidos em atividade suspeita, comportamento anômalo, transferência incomum de dados, ou qualquer IP dos padrões 8.8.8.*, 1.1.1.*, 208.67.222.*, 195.12.*
            - BAIXO: IPs com atividade incomum mas provavelmente benigna, possíveis falsos positivos.
            
            Responda apenas com uma única palavra: ALTO, MÉDIO ou BAIXO.
            """
        )
    
    def _check_ip_risk(self, ip: str) -> str:
        """Verifica o risco baseado em padrões de IPs conhecidos"""
        high_risk_ips = ["192.168.1.", "10.0.0.", "172.16.0.", "45.33.", "104.131.", "185.25.", "159.65."]
        medium_risk_ips = ["8.8.8.", "1.1.1.", "208.67.222.", "195.12."]
        
        if any(ip.startswith(prefix) for prefix in high_risk_ips):
            return "ALTO"
        elif any(ip.startswith(prefix) for prefix in medium_risk_ips):
            return "MÉDIO"
        return "BAIXO"
    
    def analyze_threat(self, threat_data: Dict[str, str]) -> str:
        """Analisa dados de ameaça usando o LLM se disponível, ou regras offline"""
        ip = str(threat_data.get("ip", ""))
        
        # Verificar risco de IP de forma centralizada
        threat_level = self._check_ip_risk(ip)
        
        # Se não estiver no modo offline e tiver um LLM configurado, use-o
        if not self.offline_mode and self.llm:
            try:
                chain = self.prompt | self.llm
                response = chain.invoke(threat_data)
                print(f"Resposta do LLM para {ip}: {response}")
                if "ALTO" in response.upper():
                    return "ALTO"
                elif "MÉDIO" in response.upper():
                    return "MÉDIO"
                else:
                    return "BAIXO"
            except Exception as e:
                print(f"Erro ao analisar ameaça com LLM: {str(e)}")
                return threat_level  # Retorna a análise baseada em IP se o LLM falhar
        
        # Modo offline: Verificar análise simplificada
        return threat_level
    
    def check_virustotal(self, ip: str) -> Dict:
        """Consulta o VirusTotal para informações sobre o IP"""
        if self.offline_mode:
            time.sleep(0.5)  # Simulação de atraso
            return {"malicious": 0, "suspicious": 1, "harmless": 70, "undetected": 15}
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"accept": "application/json", "x-apikey": self.config.vt_api_key}
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"error": f"Erro na consulta VirusTotal: {response.status_code}"}
        except requests.RequestException as e:
            return {"error": f"Erro ao consultar VirusTotal: {str(e)}"}

    def check_abuseipdb(self, ip: str) -> Dict:
        """Consulta o AbuseIPDB para informações sobre o IP"""
        if self.offline_mode:
            time.sleep(0.5)  # Simulação de atraso
            return {"abuse_confidence_score": 85, "total_reports": 7, "last_reported_at": "2023-12-15"}
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": self.config.abuse_ipdb_key}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get("data", {})
            return {"error": f"Erro na consulta AbuseIPDB: {response.status_code}"}
        except requests.RequestException as e:
            return {"error": f"Erro ao consultar AbuseIPDB: {str(e)}"}

    def analyze_threat_intelligence(self, ip: str) -> Dict:
        """Analisa ameaças usando múltiplas fontes de inteligência"""
        # Verificar se o IP já está bloqueado ou em monitoramento
        if hasattr(self, 'session_state'):
            blocked_ips = self.session_state.get("blocked_ips", set())
            monitored_ips = self.session_state.get("monitored_ips", set())
            
            if ip in blocked_ips:
                return {"level": "ALTO", "score": 9, "details": ["IP bloqueado"]}
            elif ip in monitored_ips:
                return {"level": "MÉDIO", "score": 5, "details": ["IP em monitoramento"]}
        
        # Verificar o risco do IP
        threat_level = self._check_ip_risk(ip)
        threat_score = 0
        details = [f"IP {ip} classificado como {threat_level} risco."]
        
        vt_data = self.check_virustotal(ip)
        abuse_data = self.check_abuseipdb(ip)
        
        if "error" not in vt_data:
            if vt_data.get("malicious", 0) > 0:
                threat_score += vt_data["malicious"] * 2
                details.append(f"VirusTotal: {vt_data['malicious']} maliciosos")
        
        if "error" not in abuse_data:
            if abuse_data.get("abuse_confidence_score", 0) > 50:
                threat_score += abuse_data["abuse_confidence_score"] / 25
                details.append(f"AbuseIPDB: Score {abuse_data['abuse_confidence_score']}%")
        
        level = "ALTO" if threat_score >= 5 else "MÉDIO" if threat_score >= 2 else "BAIXO"
        return {"level": level, "score": threat_score, "details": details}
