# Agente Autônomo de Segurança Cibernética

Um sistema de monitoramento e proteção de segurança cibernética 100% autônomo que detecta, analisa e responde a ameaças em tempo real utilizando Inteligência Artificial (LLM), bloqueio de firewall real e redirecionamento para honeypot.

## Características Principais

- 🤖 **100% Autônomo**: Funciona continuamente sem intervenção humana
- 🧠 **LLM Integrado**: Utiliza modelos de linguagem para análise avançada de ameaças
- 🔒 **Bloqueio Real de IPs**: Implementa regras diretas no firewall do sistema
- 🍯 **Honeypot**: Redireciona atacantes para ambiente controlado
- ⚡ **Tomada de Decisão Inteligente**: Resposta adaptativa baseada no nível de risco
- 📊 **Visualização em Tempo Real**: Interface intuitiva para monitoramento contínuo

## Arquitetura

O sistema foi implementado usando arquitetura modular orientada a objetos, dividido nos seguintes componentes:

- **Config**: Gerencia todas as configurações e chaves de API
- **SecurityLogger**: Sistema de logs com rotação de arquivos
- **ThreatIntelligence**: Análise de ameaças usando LLM e múltiplas fontes (VirusTotal, AbuseIPDB)
- **NetworkMonitor**: Monitoramento contínuo de rede em thread separada
- **SecurityAgent**: Agente de segurança com processamento paralelo e tomada de decisão autônoma
- **NotificationSystem**: Sistema de notificações para alertas
- **SecurityUI**: Interface do usuário construída com Streamlit, com atualização automática

## Requisitos

- Python 3.8+
- Streamlit
- langchain
- langchain-openai
- Plotly
- Pandas
- Requests

## Instalação

```bash
pip install -r requirements.txt
```

## Configuração

Para utilizar todas as funcionalidades:

1. Configure sua chave de API OpenAI em `config.py` para habilitar o LLM
2. Execute o aplicativo com permissões de administrador para permitir modificações no firewall
3. Opcional: Configure um honeypot real em sua rede para redirecionamento efetivo

## Uso

Execute o aplicativo Streamlit:

```bash
streamlit run main.py
```

## Níveis de Resposta Automática

O sistema responde automaticamente de acordo com o nível de ameaça:

- **Alto Risco**: Bloqueio automático no firewall OU redirecionamento para honeypot
- **Médio Risco**: Adição ao monitoramento contínuo e alerta
- **Baixo Risco**: Registro nos logs para análise posterior

## Como Funciona o Agente Autônomo

1. Ciclo de monitoramento automático a cada 10 segundos
2. Simulação automática de ataques a cada 7 segundos
3. Análise da ameaça com classificação via LLM e regras
4. Resposta automática de acordo com o nível de risco
5. Atualização da interface a cada 5 segundos
6. Bloqueio real de IPs mal-intencionados no firewall do sistema

## Diferenciais Tecnológicos

- **Autonomia Verdadeira**: Não requer intervenção humana para operação contínua
- **LLM Integrado**: Análise avançada de ameaças por modelo de linguagem
- **Ações Reais de Proteção**: Executa comandos diretos no firewall do sistema operacional
- **Arquitetura Paralela**: Threads separadas para monitoramento e análise

## Estrutura do Projeto

```
.
├── main.py                  # Arquivo principal
├── config.py                # Configurações e variáveis de ambiente 
├── logger.py                # Sistema de logs
├── threat_intelligence.py   # Análise de inteligência de ameaças com LLM
├── network_monitor.py       # Monitoramento contínuo de rede
├── security_agent.py        # Agente de segurança autônomo
├── notification.py          # Sistema de notificações
├── front.py                 # Interface Streamlit
├── requirements.txt         # Dependências do projeto
└── logs/                    # Diretório de logs (criado automaticamente)
```
