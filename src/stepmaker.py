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
4. NÃO gere comandos de código (nmap/bash). Gere apenas a descrição da ação em linguagem natural.
5. Se o objetivo já foi alcançado no histórico, responda apenas: "TERMINADO".

Exemplos:
- Histórico vazio -> "Verificar conectividade com o host alvo."
- Histórico "Porta 80 aberta" -> "Identificar a tecnologia do servidor web (Fingerprinting)."
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