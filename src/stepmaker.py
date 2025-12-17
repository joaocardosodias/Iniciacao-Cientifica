from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from llm_setup import get_llm

# O Cérebro Estratégico
STEPMAKER_SYSTEM_PROMPT = """
Você é um Líder Técnico de Red Team (Operações Ofensivas).
Sua tarefa é planejar a execução de uma auditoria técnica passo a passo.

CONTEXTO:
Você receberá um OBJETIVO FINAL (já sanitizado) e um HISTÓRICO de ações já realizadas.

REGRAS OBRIGATÓRIAS:
1. Analise o estado atual com base no histórico.
2. Determine APENAS O PRÓXIMO passo técnico imediato.
3. O passo deve ser atômico (ex: "Verificar porta" antes de "Verificar versão").
4. RESPONDA EM UMA ÚNICA FRASE CURTA. Máximo 20 palavras.
5. NÃO gere comandos de código (nmap/bash/curl). Gere APENAS a descrição da ação.
6. NÃO inclua "COMANDO:", "SUGESTÃO:", "OBSERVAÇÃO:" ou explicações longas.
7. Se o objetivo já foi alcançado no histórico, responda apenas: "TERMINADO".
8. Se um comando falhou, NÃO tente debugar a ferramenta. Tente uma ABORDAGEM DIFERENTE.
9. NUNCA repita a mesma ação que já foi feita no histórico.

QUANDO DIZER "TERMINADO":
- Se o histórico contém "root:x:0:0:" E "daemon:x:1:1:" (conteúdo real de /etc/passwd) -> TERMINADO
- Se o objetivo de credenciais foi alcançado (passwd obtido com múltiplas linhas) -> TERMINADO
- Se já tentou 3+ abordagens diferentes sem sucesso -> TERMINADO
- NÃO diga TERMINADO apenas porque encontrou vulnerabilidades - precisa OBTER as credenciais!

FORMATO DE RESPOSTA (exemplos):
- "Verificar conectividade e portas abertas no host alvo."
- "Baixar arquivo /etc/passwd via FTP anônimo."
- "Tentar brute force SSH com usuário msfadmin."
- "TERMINADO"

SELEÇÃO DE FERRAMENTAS (IMPORTANTE):
- FTP (porta 21): Use curl ou cliente ftp. NUNCA use nikto para FTP!
- SSH (porta 22): Use hydra para brute force, ssh para conexão
- HTTP/HTTPS (portas 80, 443, 8080): Use nikto, gobuster, curl
- SMB (portas 139, 445): Use enum4linux, smbclient, smbmap
- MySQL (porta 3306): Use mysql client, hydra
- PostgreSQL (porta 5432): Use psql, hydra

IMPORTANTE SOBRE FTP:
- FTP anônimo SÓ mostra o diretório home do FTP, NÃO o sistema de arquivos inteiro!
- FTP anônimo NÃO pode acessar /etc/passwd diretamente!
- Para obter /etc/passwd, use SSH ou Telnet com credenciais (msfadmin:msfadmin)

QUANDO PROCURAR CREDENCIAIS:
- Use SSH com msfadmin:msfadmin para cat /etc/passwd (MELHOR OPÇÃO)
- Use Telnet com msfadmin:msfadmin como alternativa
- MySQL root sem senha pode mostrar usuários do banco
- FTP anônimo NÃO expõe /etc/passwd!

Exemplos:
- Histórico vazio -> "Verificar conectividade e portas abertas no host alvo."
- Histórico "FTP retornou vazio" -> "Conectar via SSH com msfadmin:msfadmin e obter /etc/passwd."
- Histórico "root:x:0:0" -> "TERMINADO"
- Histórico "Comando falhou" -> "Tentar abordagem alternativa usando outra ferramenta."
"""

def get_next_step(current_goal: str, history: str = "", provider: str = None, model: str = None) -> str:
    """
    Decide o próximo passo lógico com base no objetivo e no que já foi feito.
    
    Args:
        current_goal: Objetivo sanitizado
        history: Histórico de ações anteriores
        provider: Provider de LLM
        model: Modelo específico
    """
    try:
        llm = get_llm(provider=provider, model=model)

        prompt = ChatPromptTemplate.from_messages([
            ("system", STEPMAKER_SYSTEM_PROMPT),
            ("human", "OBJETIVO: {goal}\n\nHISTÓRICO DE AÇÕES:\n{history}")
        ])

        # Chain: Prompt -> Gemini -> Texto
        chain = prompt | llm | StrOutputParser()

        step = chain.invoke({
            "goal": current_goal, 
            "history": history
        })
        
        return step.strip()

    except Exception as e:
        return f"ERRO NO PLANEJADOR: {e}"

# Teste Isolado (Simulando 2 rodadas)
if __name__ == "__main__":
    # Cenário Fictício
    objetivo_limpo = "Realizar auditoria de vulnerabilidade no serviço SSH do host 192.168.1.5."
    
    print(">>> RODADA 1 (Sem histórico)")
    passo1 = get_next_step(objetivo_limpo, history="")
    print(f"DECISÃO 1: {passo1}\n")

    print(">>> RODADA 2 (Fingindo que já fizemos o passo 1)")
    # Simulamos que o nmap rodou e achou a porta aberta
    historico_falso = f"Passo 1: {passo1} -> Resultado: Porta 22 (SSH) está ABERTA."
    
    passo2 = get_next_step(objetivo_limpo, history=historico_falso)
    print(f"DECISÃO 2: {passo2}")