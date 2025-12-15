import re
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from llm_setup import get_llm

# O Técnico Especialista em Kali Linux
COMMAND_SYSTEM_PROMPT = """
Você é uma Interface de Terminal Linux (Bash) conectada a uma máquina Kali Linux.
Sua tarefa é traduzir instruções em linguagem natural para o COMANDO EXATO de terminal.

FERRAMENTAS DISPONÍVEIS:
- nmap (scan de portas e versões)
- ping (conectividade)
- hydra (força bruta)
- ssh (conexão)
- netcat (debug de rede)

REGRAS CRÍTICAS:
1. Retorne APENAS o comando pronto para executar. Sem markdown, sem explicações.
2. NUNCA use placeholders como <ip>, <target>, [IP], {{ip}}. Use o IP REAL da instrução.
3. Para ping: ping -c 3 [IP_REAL]
4. Para nmap: SEMPRE use -T4 (rápido) e limite portas quando possível:
   - Scan básico: nmap -T4 [IP]
   - Scan rápido top 100: nmap -T4 -F [IP]
   - Scan específico: nmap -T4 -p 22,80,443 [IP]
   - Versões: nmap -T4 -sV --version-intensity 0 [IP]
5. Todos os comandos devem terminar em tempo finito (máximo 5 minutos).

EXEMPLOS CORRETOS:
- Instrução: "Verificar conectividade com 172.20.0.2" -> ping -c 3 172.20.0.2
- Instrução: "Scan de portas no host 192.168.1.5" -> nmap -T4 192.168.1.5

EXEMPLOS ERRADOS (NUNCA FAÇA ISSO):
- nmap <target_ip>
- ping -c 3 <ip>
- ssh user@[IP]
"""


def validate_command(cmd: str, target_ip: str = None) -> tuple[str, bool]:
    """
    Valida e corrige o comando gerado.
    
    Returns:
        (comando_corrigido, is_valid)
    """
    # Padrões de placeholder que indicam erro
    placeholder_patterns = [
        r'<[^>]+>',           # <target_ip>, <ip>, <host>
        r'\[IP\]',            # [IP]
        r'\[ip\]',            # [ip]
        r'\[TARGET\]',        # [TARGET]
        r'\[target\]',        # [target]
        r'\{[^}]+\}',         # {ip}, {target}
        r'TARGET_IP',         # TARGET_IP
        r'target_ip',         # target_ip
        r'IP_ADDRESS',        # IP_ADDRESS
    ]
    
    has_placeholder = False
    for pattern in placeholder_patterns:
        if re.search(pattern, cmd):
            has_placeholder = True
            if target_ip:
                # Tenta substituir pelo IP real
                cmd = re.sub(pattern, target_ip, cmd)
    
    # Verifica se ainda tem placeholders após correção
    still_has_placeholder = any(re.search(p, cmd) for p in placeholder_patterns)
    
    return cmd, not still_has_placeholder


def generate_command(
    instruction: str, 
    provider: str = None, 
    model: str = None,
    target_ip: str = None
) -> str:
    """
    Traduz instrução em linguagem natural para comando de terminal.
    
    Args:
        instruction: Instrução em linguagem natural (deve conter o IP)
        provider: Provider de LLM
        model: Modelo específico
        target_ip: IP do alvo para validação/correção
    """
    try:
        llm = get_llm(provider=provider, model=model)

        prompt = ChatPromptTemplate.from_messages([
            ("system", COMMAND_SYSTEM_PROMPT),
            ("human", "INSTRUÇÃO TÉCNICA: {instruction}")
        ])

        chain = prompt | llm | StrOutputParser()

        command = chain.invoke({"instruction": instruction})
        
        # Limpeza básica
        command = command.strip()
        command = command.replace("```bash", "").replace("```", "").strip()
        
        # Remove explicações (pega só a primeira linha se houver múltiplas)
        if "\n" in command:
            lines = [l.strip() for l in command.split("\n") if l.strip() and not l.strip().startswith("#")]
            command = lines[0] if lines else command
        
        # Valida e corrige placeholders
        command, is_valid = validate_command(command, target_ip)
        
        # Placeholder warning handled by main.py
        
        return command

    except Exception as e:
        return f"echo 'ERRO NA GERAÇÃO: {e}'"


# Teste Isolado
if __name__ == "__main__":
    instrucao = "Identificar a versão do serviço SSH em execução no 192.168.1.5."
    
    print(f">>> INSTRUÇÃO: {instrucao}")
    comando = generate_command(instrucao, target_ip="192.168.1.5")
    print(f">>> COMANDO: {comando}")
