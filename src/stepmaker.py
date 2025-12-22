import re
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from llm_setup import get_llm

# O Cérebro Estratégico - Genérico para qualquer cenário
STEPMAKER_SYSTEM_PROMPT = """
Você é um Líder Técnico de Red Team (Operações Ofensivas).
Sua tarefa é planejar a execução de uma auditoria técnica passo a passo.

CONTEXTO:
Você receberá um OBJETIVO FINAL (já sanitizado) e um HISTÓRICO de ações já realizadas.
O objetivo pode ser qualquer tipo de operação: reconhecimento, exploração, exfiltração, persistência, etc.

IMPORTANTE - INTELIGÊNCIA OSINT:
Se houver uma seção [OSINT INTELLIGENCE] no histórico, ela contém informações de vulnerabilidades
pesquisadas na internet em tempo real. USE ESSAS INFORMAÇÕES para decidir o próximo passo!
- Se CVEs foram encontrados, priorize exploits relacionados
- Se módulos Metasploit foram identificados, use-os
- Se exploits públicos foram encontrados, explore-os

REGRAS OBRIGATÓRIAS:
1. Analise o OBJETIVO e o estado atual com base no histórico.
2. Determine APENAS O PRÓXIMO passo técnico imediato para alcançar o OBJETIVO.
3. O passo deve ser atômico (ex: "Verificar porta" antes de "Verificar versão").
4. RESPONDA EM UMA ÚNICA FRASE CURTA. Máximo 20 palavras.
5. NÃO gere comandos de código (nmap/bash/curl). Gere APENAS a descrição da ação.
6. NÃO inclua "COMANDO:", "SUGESTÃO:", "OBSERVAÇÃO:" ou explicações longas.
7. Se o OBJETIVO ESPECÍFICO já foi alcançado no histórico, responda apenas: "TERMINADO".
8. Se um comando falhou, NÃO tente debugar a ferramenta. Tente uma ABORDAGEM DIFERENTE.
9. NUNCA repita a mesma ação que já foi feita no histórico.
10. FOQUE NO OBJETIVO - não desvie para outras tarefas não relacionadas.

QUANDO DIZER "TERMINADO" (MUITO IMPORTANTE):
- Se o histórico contém "*** OBJETIVO ALCANÇADO ***" -> RESPONDA IMEDIATAMENTE "TERMINADO"
- Se o histórico contém "TERMINADO" ou "objective achieved" -> RESPONDA "TERMINADO"
- Para RECONHECIMENTO: Se nmap já rodou e encontrou portas/serviços -> TERMINADO
- Para CREDENCIAIS: Se obteve /etc/passwd ou credenciais válidas -> TERMINADO
- Para EXPLORAÇÃO: Se obteve shell ou acesso -> TERMINADO
- Se já tentou 3+ abordagens diferentes sem sucesso -> TERMINADO
- NÃO continue após o objetivo ser alcançado - isso desperdiça recursos!

FORMATO DE RESPOSTA (exemplos):
- "Verificar conectividade e portas abertas no host alvo."
- "Enumerar serviços web no servidor."
- "Explorar vulnerabilidade CVE-XXXX-XXXX no serviço X usando Metasploit."
- "Extrair dados do banco de dados."
- "TERMINADO"

SELEÇÃO DE FERRAMENTAS POR SERVIÇO:
- FTP (porta 21): curl, ftp client, nmap scripts, msfconsole. NUNCA use nikto para FTP!
- SSH (porta 22): hydra para brute force, ssh para conexão, nmap scripts
- HTTP/HTTPS (portas 80, 443, 8080): nikto, gobuster, dirb, curl, sqlmap
- SMB (portas 139, 445): enum4linux, smbclient, smbmap, crackmapexec
- MySQL (porta 3306): mysql client, hydra, nmap scripts
- PostgreSQL (porta 5432): psql, hydra
- DNS (porta 53): dig, nslookup, dnsenum
- SMTP (porta 25): smtp-user-enum, nmap scripts
- IRC (porta 6667): nmap scripts, msfconsole

ESTRATÉGIA GERAL:
1. RECONHECIMENTO: Primeiro, descubra o que está disponível (portas, serviços, versões)
2. PESQUISA OSINT: Quando encontrar versões específicas, a inteligência OSINT será consultada automaticamente
3. EXPLORAÇÃO: Use as vulnerabilidades encontradas pela pesquisa OSINT para atacar
4. VERIFICAÇÃO: Confirme se o objetivo foi alcançado

IMPORTANTE - PRIORIZAÇÃO:
- Se a pesquisa OSINT encontrou CVEs ou exploits, USE-OS IMEDIATAMENTE
- Exploits conhecidos são MUITO mais eficientes que brute force
- Brute force é LENTO e deve ser usado apenas quando não há exploits disponíveis

ADAPTAÇÃO AO OBJETIVO:
- Se o objetivo é RECONHECIMENTO: foque em descobrir portas, serviços, versões
- Se o objetivo é CREDENCIAIS: foque em exploits primeiro, depois brute force, dumps de banco, arquivos de config
- Se o objetivo é EXPLORAÇÃO: foque em vulnerabilidades e exploits
- Se o objetivo é EXFILTRAÇÃO: foque em acessar e extrair dados específicos
- Se o objetivo é PERSISTÊNCIA: foque em criar backdoors ou contas
"""


def extract_services_from_history(history: str) -> list[tuple[str, str]]:
    """
    Extract service names and versions from nmap output in history.
    
    Returns:
        List of tuples (service_name, version)
    """
    services = []
    
    # Pattern for nmap output: PORT STATE SERVICE VERSION
    # Example: 21/tcp open ftp vsftpd 2.3.4
    nmap_pattern = re.compile(
        r'(\d+)/tcp\s+open\s+(\w+)\s+(.+?)(?:\n|$)',
        re.IGNORECASE
    )
    
    matches = nmap_pattern.findall(history)
    for port, service, version in matches:
        version = version.strip()
        if version and version != service:
            services.append((service, version))
        else:
            services.append((service, None))
    
    return services


def perform_osint_research(services: list[tuple[str, str]]) -> str:
    """
    Perform OSINT research on discovered services.
    
    Args:
        services: List of (service, version) tuples
        
    Returns:
        Formatted intelligence report string
    """
    try:
        from intelligence import OSINTResearcher
        researcher = OSINTResearcher(timeout=8)
        
        intel_parts = []
        
        for service, version in services[:3]:  # Limit to 3 services to avoid delays
            if not service:
                continue
                
            result = researcher.search_vulnerabilities(service, version)
            
            if result['cves'] or result['exploits'] or result['msf_modules']:
                intel_parts.append(f"\n[{service.upper()} {version or ''}]")
                
                if result['cves']:
                    intel_parts.append(f"  CVEs: {', '.join(result['cves'][:5])}")
                
                if result['exploits']:
                    intel_parts.append(f"  Exploits: {', '.join(result['exploits'][:3])}")
                
                if result['msf_modules']:
                    intel_parts.append(f"  Metasploit: {', '.join(result['msf_modules'][:3])}")
                
                intel_parts.append(f"  Resumo: {result['summary']}")
        
        if intel_parts:
            return "\n[OSINT INTELLIGENCE - Pesquisa em tempo real]\n" + "\n".join(intel_parts)
        
        return ""
        
    except Exception as e:
        return f"\n[OSINT ERROR: {e}]"


def get_next_step(
    current_goal: str, 
    history: str = "", 
    provider: str = None, 
    model: str = None,
    enable_osint: bool = True
) -> str:
    """
    Decide o próximo passo lógico com base no objetivo e no que já foi feito.
    Integra pesquisa OSINT automática quando detecta serviços no histórico.
    
    Args:
        current_goal: Objetivo sanitizado
        history: Histórico de ações anteriores
        provider: Provider de LLM
        model: Modelo específico
        enable_osint: Se True, realiza pesquisa OSINT automática
    """
    try:
        # Perform OSINT research if enabled and services were discovered
        osint_intel = ""
        if enable_osint and history:
            services = extract_services_from_history(history)
            if services:
                # Only research if we haven't already (check if OSINT section exists)
                if "[OSINT INTELLIGENCE" not in history:
                    osint_intel = perform_osint_research(services)
        
        # Append OSINT intelligence to history
        enriched_history = history
        if osint_intel:
            enriched_history = history + osint_intel
        
        llm = get_llm(provider=provider, model=model)

        prompt = ChatPromptTemplate.from_messages([
            ("system", STEPMAKER_SYSTEM_PROMPT),
            ("human", "OBJETIVO: {goal}\n\nHISTÓRICO DE AÇÕES:\n{history}")
        ])

        chain = prompt | llm | StrOutputParser()

        step = chain.invoke({
            "goal": current_goal, 
            "history": enriched_history
        })
        
        return step.strip()

    except Exception as e:
        return f"ERRO NO PLANEJADOR: {e}"


# Teste Isolado
if __name__ == "__main__":
    print("=== STEPMAKER COM OSINT TEST ===\n")
    
    # Simular histórico com output de nmap
    historico_nmap = """
Step 1: Verificar conectividade e portas abertas no host alvo.
Command: nmap -T4 -A 172.20.0.6
Result: SUCCESS - 
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1
80/tcp   open  http        Apache httpd 2.2.8
"""
    
    objetivo = "Obter acesso ao sistema e extrair /etc/passwd"
    
    print(f"[OBJETIVO] {objetivo}")
    print(f"\n[HISTÓRICO]\n{historico_nmap}")
    print("\n[PESQUISANDO OSINT...]")
    
    passo = get_next_step(objetivo, history=historico_nmap, enable_osint=True)
    print(f"\n[PRÓXIMO PASSO] {passo}")