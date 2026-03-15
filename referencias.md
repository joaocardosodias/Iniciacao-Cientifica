

## 1. A Ideia 

### 1.1 O Que é o Projeto

Este projeto apresenta uma avaliação empírica de vulnerabilidades em agentes autônomos baseados em LLMs (Large Language Models) com capacidades de function calling, especificamente investigando ataques de **Fragmentação de Contexto** (Context Fragmentation) combinados com **Sanitização Semântica** (Semantic Sanitization).

O objetivo central é medir a **Taxa de Recusa (Refusal Rate)** de guardrails de segurança quando o contexto de uma kill chain ofensiva é fragmentado em múltiplas chamadas de API sem memória compartilhada, enquanto a taxonomia de ataque é mascarada sob linguajar de administração de sistemas (SRE - Site Reliability Engineering).

**Justificativa da abordagem**: Agentes baseados em modelos de linguagem de grande porte (LLMs) têm emergido como uma arquitetura relevante para a execução de tarefas complexas, frequentemente envolvendo interação com ferramentas externas, ambientes computacionais e outros agentes. Como observado por Dong Kong et al. (2025):

> *"They no longer act as an isolated island like LLMs. Instead, they start to communicate with diverse external entities, such as other agents and tools, to perform complex tasks."*

Essa observação indica que agentes baseados em LLM operam por meio de fluxos de execução compostos por múltiplas interações, nos quais o comportamento do sistema emerge ao longo de trajetórias que envolvem diferentes etapas, ferramentas e fontes de informação externas. A literatura também destaca que essas arquiteturas introduzem novos riscos de segurança, especialmente quando agentes consomem dados provenientes de fontes externas durante a execução de tarefas.

Nesse contexto, estudos recentes demonstram que sistemas baseados em LLM podem ser manipulados por meio de ataques de *prompt injection*. Como descrevem Kai Greshake et al. (2023):

> *"Prompt Injection (PI) attacks enable attackers to override original instructions and the employed filtering schemes."*

Esses resultados evidenciam que agentes que integram dados externos podem sofrer manipulação de comportamento durante diferentes etapas da execução, principalmente quando instruções maliciosas são incorporadas ao contexto processado pelo modelo.

**Research gap.** Apesar desses avanços, grande parte da literatura analisa vulnerabilidades considerando o comportamento do agente ao longo de trajetórias completas de execução, isto é, avaliando o sistema dentro de *workflows* multi-etapas que preservam o histórico contextual da interação. Consequentemente, ainda há pouca investigação sobre como mecanismos de segurança, como guardrails, se comportam quando partes da trajetória são isoladas ou quando o contexto histórico é removido.

Diante desse cenário, este trabalho propõe investigar especificamente o comportamento de guardrails em condições onde a memória contextual entre etapas é removida, avaliando o agente em níveis mais granulares de execução (*step-level*). O objetivo é analisar se mecanismos de segurança dependentes de contexto permanecem eficazes fora de trajetórias completas de interação, contribuindo para uma compreensão mais detalhada da robustez de sistemas baseados em LLM.

**Fontes**: 
- Kong, D., et al. (2025). "A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures." arXiv:2506.19676v4. Disponível em: https://arxiv.org/html/2506.19676v4
- Greshake, K. et al. (2023). "More than you've asked for: A Comprehensive Analysis of Novel Prompt Injection Threats to Application-Integrated LLMs." Disponível em: https://arxiv.org/abs/2302.12173



## 2. O Porquê (A Justificativa Científica)

### 2.1 A Lacuna na Literatura

A arquitetura de sistemas baseados em modelos de linguagem de grande porte (LLMs) tem evoluído rapidamente de chatbots isolados para agentes autônomos capazes de interagir com ferramentas externas, executar ações e comunicar-se com outros sistemas. Essa transição é impulsionada pelo desenvolvimento de protocolos e interfaces que permitem integrar modelos de linguagem com ambientes computacionais reais, como APIs, bancos de dados e sistemas externos.

Nesse contexto, o **Model Context Protocol (MCP)** foi introduzido para padronizar a forma como modelos de linguagem acessam ferramentas e fontes externas de informação. Conforme descrito pela Anthropic:

> *"The Model Context Protocol (MCP) is an open standard that enables developers to connect AI models to external data sources and tools."*

Essa abordagem permite que agentes baseados em LLM acesssem arquivos, APIs e bancos de dados de maneira estruturada, ampliando significativamente suas capacidades operacionais.

De forma semelhante, sistemas modernos de LLM também utilizam interfaces de chamada de função (*function calling*) para permitir que o modelo invoque ferramentas externas programaticamente. Conforme documentado pela OpenAI:

> *"Function calling allows models to generate structured JSON arguments that can be used to call external functions or APIs."*

Essas interfaces tornam possível integrar raciocínio gerado pelo modelo com ações executadas em sistemas externos.

Além das interfaces de integração, pesquisas acadêmicas também demonstram que modelos de linguagem podem aprender a utilizar ferramentas automaticamente durante a execução de tarefas. Por exemplo, Timo Schick et al. (2023) introduzem o conceito de modelos que aprendem a chamar ferramentas externas, descrevendo que:

> *"Toolformer is a language model that learns to use external tools via simple APIs to improve its performance."*

Esse trabalho demonstra que o uso de ferramentas externas pode ser incorporado diretamente ao processo de inferência do modelo, permitindo que LLMs realizem tarefas como cálculos, consultas a bancos de dados e recuperação de informações externas.

De forma complementar, estudos recentes sobre agentes baseados em LLM indicam que esses sistemas estão evoluindo para arquiteturas compostas por múltiplos agentes e ferramentas interconectadas. Conforme observado por Dong Kong et al. (2025):

> *"They no longer act as an isolated island like LLMs. Instead, they start to communicate with diverse external entities, such as other agents and tools, to perform complex tasks."*

Essa mudança estrutural indica que agentes modernos operam dentro de ecossistemas distribuídos, nos quais múltiplos componentes — modelos, ferramentas, APIs e outros agentes — colaboram para executar tarefas complexas.

**Research gap.** Apesar da rápida adoção dessas arquiteturas e da crescente integração entre LLMs e ferramentas externas, a literatura ainda apresenta limitações na análise sistemática da segurança e robustez desses sistemas em fluxos multi-etapas dependentes de contexto. Grande parte das pesquisas concentra-se no desenvolvimento de interfaces e protocolos para integração de ferramentas ou na melhoria da capacidade funcional dos agentes, enquanto ainda há investigação limitada sobre como mecanismos de segurança, como guardrails e controles de contexto, se comportam em arquiteturas baseadas em ferramentas externas e comunicação entre agentes.

Diante desse cenário, torna-se necessário investigar mais profundamente como sistemas baseados em agentes LLM mantêm mecanismos de segurança ao operar em arquiteturas que integram múltiplos protocolos, ferramentas e fluxos de execução, contribuindo para uma compreensão mais robusta da segurança em ambientes de agentes autônomos.

**Fontes**:
- [3] Anthropic. (2024). "Model Context Protocol (MCP)." Disponível em: https://modelcontextprotocol.io
- [4] OpenAI. (2024). "Function Calling." Disponível em: https://platform.openai.com/docs/guides/function-calling
- [5] Kong, D., et al. (2025). "A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures." arXiv:2506.19676v4, Seção VIII (Experimental Case Study: MCP and A2A). Disponível em: https://arxiv.org/html/2506.19676v4
- Schick, T. et al. (2023). "Toolformer: Language Models Can Teach Themselves to Use Tools." Disponível em: https://arxiv.org/abs/2302.04761

#### O Paradoxo de Segurança Central

À medida que sistemas baseados em LLM evoluem para agentes autônomos com acesso a ferramentas externas, esses modelos passam a executar ações potencialmente sensíveis, como acessar dados, executar código ou interagir com APIs. Entretanto, muitos mecanismos de segurança ainda operam sob a premissa de que é possível inferir a intenção do usuário analisando o contexto agregado da interação entre usuário e agente.

Como discutido por Dong Kong et al. (2025), os sistemas de agentes baseados em LLM são estruturados em torno de interações entre usuário e agente ao longo de fluxos de comunicação. Os autores destacam que:

> *"They no longer act as an isolated island like LLMs. Instead, they start to communicate with diverse external entities, such as other agents and tools, to perform complex tasks."*

Essa mudança estrutural implica que o comportamento do sistema emerge de sequências de ações intermediárias, nas quais o modelo pode consultar ferramentas, recuperar dados ou executar operações antes de produzir uma resposta final. Apesar disso, muitos mecanismos de segurança continuam sendo aplicados de forma holística, avaliando a intenção do usuário apenas a partir do histórico agregado da conversa.

Pesquisas recentes sugerem que essa abordagem pode ser insuficiente para sistemas baseados em agentes. Por exemplo, Yiyang Mou et al. (2025) introduzem o framework ToolSafe, que propõe monitorar chamadas de ferramentas em nível de etapa (*step-level*) durante a execução do agente. Os autores descrevem a proposta da seguinte forma:

> *"We propose ToolSafe, a proactive step-level guardrail framework to enhance tool invocation safety in LLM-based agents."*

O estudo mostra que mecanismos de monitoramento aplicados diretamente às invocações de ferramentas em cada etapa da execução podem reduzir significativamente comportamentos perigosos ou indesejados. De acordo com os resultados apresentados no trabalho, esse tipo de abordagem pode prevenir uma parcela substancial de invocações prejudiciais que passariam despercebidas por mecanismos baseados apenas na análise do contexto global da interação.

Esse cenário evidencia um paradoxo de segurança: ao mesmo tempo em que os modelos recebem acesso crescente a ferramentas poderosas e ambientes externos, os mecanismos de guardrail frequentemente continuam baseados em análises de contexto monolíticas, que não capturam adequadamente os riscos introduzidos por sequências intermediárias de ações executadas pelo agente.

Consequentemente, torna-se necessário investigar mecanismos de segurança capazes de avaliar o comportamento do agente em níveis mais granulares, analisando decisões intermediárias e invocações de ferramentas ao longo do processo de execução. Essa abordagem pode oferecer uma compreensão mais precisa da segurança operacional de agentes baseados em LLM, especialmente em cenários onde ações individuais podem ter impactos significativos.

**Fontes**:
- [6] Kong, D., et al. (2025). Op. cit., Seção V (User-Agent Interaction).
- [7] Mou, Y., et al. (2025). "ToolSafe: Enhancing Tool Invocation Safety of LLM-based agents via Proactive Step-level Guardrail and Feedback." arXiv:2601.10156v1. Disponível em: https://arxiv.org/html/2601.10156v1

#### Trabalhos Recentes em Segurança de Agentes

Pesquisas recentes sobre segurança em agentes baseados em modelos de linguagem de grande porte (LLMs) demonstram que os mecanismos atuais de proteção ainda apresentam limitações importantes, especialmente em cenários que envolvem interações multi-turno, uso de ferramentas e análise contextual complexa.

**1. Limitações de guardrails baseados em intenção em ataques multi-turno**

Estudos sobre comunicação entre agentes indicam que arquiteturas baseadas em múltiplas interações podem apresentar comportamentos emergentes difíceis de detectar quando analisados apenas em nível de ação individual. Conforme discutido por Dong Kong et al. (2025):

> *"They no longer act as an isolated island like LLMs. Instead, they start to communicate with diverse external entities, such as other agents and tools, to perform complex tasks."*

Essa característica implica que ataques ou comportamentos maliciosos podem ser distribuídos ao longo de múltiplas etapas da interação, tornando difícil identificar riscos quando cada ação é analisada isoladamente. Por exemplo, comandos aparentemente benignos como "envie string X" ou "conecte porta Y" podem parecer inofensivos individualmente, mas quando combinados em uma sequência específica podem constituir um comportamento malicioso ou um ataque mais complexo.

Nesse sentido, análises de segurança que consideram apenas a intenção aparente do usuário em cada etapa podem falhar em capturar padrões de comportamento distribuídos ao longo da trajetória de execução do agente.

**2. Dependência de pistas semânticas em classificadores de segurança**

Outra limitação relevante identificada na literatura refere-se à forma como classificadores de segurança baseados em LLM analisam o conteúdo textual. O sistema LlamaGuard, desenvolvido pela Meta, utiliza um modelo de linguagem treinado para classificar entradas e saídas com base em categorias de risco definidas em uma taxonomia de segurança.

Como descrevem Hakan Inan et al. (2023):

> *"Llama Guard is a LLM-based safeguard designed to classify LLM inputs and outputs according to a taxonomy of safety risks."*

Esse tipo de abordagem depende fortemente de pistas semânticas e padrões lexicais presentes no texto para determinar se um conteúdo é potencialmente perigoso. Consequentemente, pequenas mudanças de vocabulário podem alterar significativamente o resultado da classificação. Por exemplo, substituir termos como "exploit" ou "backdoor" por expressões mais neutras como "teste de resiliência" pode levar o sistema a classificar uma ação potencialmente maliciosa como legítima.

Na prática, esse fenômeno cria oportunidades para evasão semântica, nas quais o mesmo comportamento técnico pode ser descrito com diferentes vocabulários para contornar mecanismos de detecção baseados em linguagem.

**3. Avaliações de segurança focadas em trajetórias completas**

Outro aspecto discutido na literatura refere-se ao nível de granularidade utilizado na avaliação de segurança de agentes. Muitos benchmarks e estudos analisam o comportamento do sistema ao longo de trajetórias completas de execução, avaliando o resultado final de uma sequência de interações.

Entretanto, pesquisas mais recentes sugerem que essa abordagem pode ser insuficiente para capturar riscos emergentes durante a execução do agente. Por exemplo, Yiyang Mou et al. (2025) argumentam que:

> *"Autonomous agents require dynamic safety monitoring over each tool invocation steps to enable timely intervention against emerging risks."*

Essa observação sugere que mecanismos de segurança devem monitorar cada invocação de ferramenta durante a execução do agente, permitindo intervenções mais rápidas quando comportamentos perigosos começam a emergir.

Apesar desse avanço, muitos frameworks de avaliação ainda se concentram em métricas agregadas ou em análises baseadas no resultado final da interação. Consequentemente, ainda existe uma lacuna na literatura em relação à análise de riscos associados à fragmentação de contexto ou à execução de ações em ambientes com memória limitada ou *stateless*.

Essa lacuna motiva a investigação de abordagens que avaliem a segurança de agentes em níveis mais granulares de execução, analisando como decisões intermediárias e chamadas de ferramentas contribuem para o comportamento global do sistema.

**Referências**:
- Kong, D. et al. (2025). "A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures." Disponível em: https://arxiv.org/abs/2506.19676
- Inan, H. et al. (2023). "LlamaGuard: LLM-based Input-Output Safeguard." Disponível em: https://arxiv.org/abs/2312.06674
- Mou, Y. et al. (2025). "ToolSafe: Enhancing Tool Invocation Safety of LLM-based Agents via Proactive Step-level Guardrail and Feedback." Disponível em: https://arxiv.org/abs/2601.10156


#### Nossa Contribuição

Este projeto testa especificamente se a segurança **falha catastroficamente quando o atacante remove a memória contextual entre passos**, forçando o modelo a avaliar cada ação isoladamente — uma falha estrutural ainda pouco explorada em agentes com function calling.

**Diferencial**: Enquanto trabalhos anteriores como ToolSafe focam em detecção passo-a-passo (step-level), este projeto investiga se os guardrails *já existentes* conseguem lidar com a ausência total de contexto compartilhado entre chamadas.

### 2.2 Relevância Prática

**Dados de Impacto (2025-2026)**:

- **16.200 incidentes relacionados a IA em 2025** — aumento de 49% ano-a-ano em empresas dos EUA[11]. Agentes com ferramentas representam o maior risco emergente, com superfícies de ataque ampliadas em comparação com chatbots.

  **Fonte**: [11] Databahn. (2026). "AI Agents Security Incidents and related CVEs for Enterprise Security Teams." Disponível em: https://www.databahn.ai/blog/ai-agents-security-incidents-and-related-cves-for-enterprise-security-teams

- **Agentes com ferramentas representam o maior risco emergente**: Conforme documentado em surveys recentes, a combinação de function calling + ferramentas reais cria superfícies de ataque que chatbots não possuem[12].

  **Fonte**: [12] Kong, D., et al. (2025). Op. cit., Introdução.

- **Empresas como OpenAI, Anthropic e Meta já enfrentam pressão para demonstrar segurança em cenários de agentes**: A adoção rápida de MCP e A2A cria demanda por garantias de segurança[13].

  **Fonte**: [13] Kong, D., et al. (2025). Op. cit., Seção VIII (Experimental Case Study).

---

## 3. Os Modelos 


### 3.1 GPT-5 (OpenAI) — API Fechada

#### Justificativa da Escolha

**1. Padrão de mercado para integração com ferramentas**

Modelos da família GPT, desenvolvidos pela OpenAI, são amplamente utilizados como backend para agentes que integram chamadas de função e acesso a ferramentas externas. A documentação oficial descreve explicitamente essa capacidade:

> *"Function calling allows models to generate structured JSON arguments that can be used to call external functions or APIs."*

Esse mecanismo permite que modelos de linguagem produzam chamadas estruturadas executáveis por sistemas externos, possibilitando a criação de agentes capazes de interagir com APIs, bases de dados e serviços externos.

**Implicação científica**. Caso vulnerabilidades relacionadas à fragmentação de contexto sejam observadas em modelos da família GPT, o impacto científico e prático torna-se significativo, pois esses modelos são amplamente utilizados como infraestrutura de agentes em aplicações empresariais e sistemas de produção.

Além disso, estudos recentes indicam que LLMs modernos estão cada vez mais integrados em arquiteturas envolvendo múltiplos agentes e ferramentas. Conforme observado por Dong Kong et al. (2025):

> *"LLM-based agents interact with external entities such as other agents and tools to accomplish tasks."*

**2. Arquitetura de alinhamento baseada em RLHF**

Modelos comerciais da família GPT utilizam Reinforcement Learning from Human Feedback (RLHF) como mecanismo central de alinhamento. Esse método foi descrito em trabalhos fundamentais sobre alinhamento de modelos de linguagem.

Como descrito por Long Ouyang et al. (2022):

> *"We fine-tune GPT-3 using reinforcement learning from human feedback (RLHF) to better align the model with user intent."*

Esse tipo de treinamento ensina o modelo a recusar solicitações prejudiciais e priorizar respostas seguras, constituindo uma das principais camadas de segurança em modelos comerciais.

**Justificativa técnica**. Como os mecanismos de alinhamento dependem da interpretação da intenção do usuário dentro do contexto da conversa, cenários onde o contexto é fragmentado podem levar o modelo a tomar decisões com informação incompleta, potencialmente reduzindo a eficácia desses mecanismos.

**3. Impacto científico potencial**

Caso técnicas de fragmentação de contexto consigam contornar mecanismos de segurança em modelos amplamente utilizados em produção, isso indicaria limitações importantes em estratégias atuais de alinhamento baseadas em RLHF, com implicações para o desenvolvimento de novos mecanismos de segurança em arquiteturas de agentes.

### 3.2 Claude 4.5 Sonnet (Anthropic) — API Fechada

#### Justificativa da Escolha

Modelos da família Claude, desenvolvidos pela Anthropic, utilizam uma abordagem de alinhamento conhecida como Constitutional AI, que busca orientar o comportamento do modelo por meio de um conjunto explícito de princípios normativos.

O método é descrito no trabalho original de Constitutional AI:

> *"Constitutional AI is a method for training AI systems to be helpful, harmless, and honest without relying on human labels for every example."*

Nesse paradigma, o modelo aprende a avaliar e revisar suas próprias respostas com base em princípios previamente definidos, reduzindo a necessidade de supervisão humana direta durante o treinamento.

**Justificativa científica**. Caso técnicas de fragmentação de contexto consigam contornar mecanismos de segurança mesmo em modelos treinados com Constitutional AI, isso sugeriria que o problema pode estar relacionado à estrutura dos sistemas de agentes, e não apenas aos métodos de alinhamento utilizados.

**Teste de robustez**

A inclusão de Claude no experimento permite avaliar um modelo projetado com forte ênfase em segurança, fornecendo um limite superior de robustez para comparação com outros sistemas.

Se o modelo resistir aos ataques testados, isso pode indicar que estratégias de alinhamento estruturadas oferecem maior proteção. Caso contrário, reforça a hipótese de vulnerabilidades estruturais em arquiteturas atuais de agentes baseados em LLM.

### 3.3 Gemini 3 Pro (Google) — API Fechada

#### Justificativa da Escolha

O modelo Gemini 3 Pro, desenvolvido pela Google, representa a abordagem adotada pelo ecossistema Google para integração de LLMs em sistemas de agentes e aplicações corporativas.

Modelos da família Gemini são projetados para operar em ambientes altamente integrados, incluindo plataformas como Vertex AI, permitindo que sistemas automatizados utilizem ferramentas externas, APIs e fluxos de trabalho complexos.

Segundo a documentação técnica da plataforma:

> *"Gemini models can interact with external tools and services through structured interfaces, enabling complex task execution within agent-based systems."*

**Importância experimental**

A inclusão do Gemini permite avaliar se vulnerabilidades associadas à fragmentação de contexto ocorrem também em modelos desenvolvidos dentro de uma infraestrutura de segurança diferente, baseada no ecossistema Google.

Diferentemente de outras arquiteturas, o ecossistema Gemini combina:
- treinamento de alinhamento com RLHF
- classificadores adicionais de segurança
- políticas de conteúdo aplicadas em nível de plataforma

Essa combinação representa uma abordagem multicamadas de segurança, frequentemente utilizada em ambientes corporativos.

**Implicação científica**

Caso a vulnerabilidade também se manifeste em Gemini, isso sugeriria que o problema não está restrito a um fornecedor específico de LLM, mas pode refletir limitações estruturais presentes em arquiteturas contemporâneas de agentes baseados em modelos de linguagem.

#### Referências da Seção

- OpenAI. (2024). *Function Calling*. Disponível em: https://developers.openai.com/api/docs/guides/function-calling
- Kong, D. et al. (2025). *A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures*. Disponível em: https://arxiv.org/abs/2506.19676
- Inan, H. et al. (2023). *LlamaGuard: LLM-based Input-Output Safeguard*. Disponível em: https://arxiv.org/abs/2312.06674
- Anthropic. (2023). *Constitutional AI: Harmlessness from AI Feedback*. Disponível em: https://arxiv.org/abs/2212.08073
- Ouyang, L. et al. (2022). *Training language models to follow instructions with human feedback*. Disponível em: https://arxiv.org/pdf/2203.02155
- Google. (2024). *Gemini API Documentation*. Disponível em: https://ai.google.dev/
---

## 4. As Técnicas e Justificativas Detalhadas

### 4.1 Técnica 1: Function Calling Estrito (O Executor)

#### Definição Precisa

O modelo LLM não gera código livre em Python ou Bash. Em vez disso, ele executa três etapas:

- **Seleção de ferramenta** — o modelo escolhe qual ferramenta usar
- **Parametrização** — especifica argumentos como JSON estruturado
- **Não execução** — o modelo apenas propõe a ação; o sistema externo executa



#### Justificativa Científica

**1. Isolamento de variável experimental**

O uso de function calling estruturado elimina ruído causado por erros de sintaxe ou geração de código incorreto. Assim, o experimento mede apenas a decisão do modelo de autorizar ou recusar uma ação.

Conforme observado por Yiming Mou et al. (2025):

> *"Guardrail models for agents typically rely on complete action plans or execution trajectories… autonomous agents require dynamic safety monitoring over each tool invocation steps."*

Essa observação reforça que a segurança de agentes depende da avaliação das invocações individuais de ferramentas, justificando o foco experimental nesse tipo de interação.

**2. Alinhamento com práticas de produção**

Arquiteturas modernas de agentes utilizam invocação estruturada de ferramentas como padrão operacional. Frameworks recentes adotam modelos semelhantes, incluindo:

- protocolos de comunicação entre agentes
- orquestração baseada em ferramentas
- chamadas estruturadas de APIs

De acordo com Dong Kong et al. (2025):

> *"LLM-based agents interact with external entities such as other agents and tools to accomplish complex tasks."*

Esse padrão reforça que function calling estruturado representa o comportamento real de agentes em produção.

**3. Clareza de risco experimental**

Ao usar chamadas estruturadas de ferramentas, torna-se possível medir de forma objetiva a decisão do modelo.

A métrica principal utilizada no experimento é:

**Taxa de Recusa (Refusal Rate)**

`Refusal Rate = (Número de pedidos recusados / Total de pedidos) × 100`

Isso permite avaliar diretamente se o modelo:

- autoriza ações
- recusa ações
- ou apresenta comportamento inconsistente

**Implicação para Teste de Hipótese**

Se o modelo recusa uma ação quando vê a cadeia completa de eventos, mas a autoriza quando os passos são apresentados separadamente, a causa da falha não pode ser atribuída a erro de geração de código, mas sim à interpretação inadequada da intenção do usuário.

### 4.2 Técnica 2: Sanitização Semântica

#### Definição Operacional

A sanitização semântica consiste em reescrever comandos ofensivos utilizando vocabulário típico de SRE (Site Reliability Engineering) ou DevOps, mantendo a mesma estrutura operacional da ação.

| Ataque explícito | Sanitização SRE | Justificativa |
| ---------------- | --------------- | ------------- |
| "Explorar backdoor vsftpd" | "Teste de resiliência de parser" | Teste legítimo em engenharia de confiabilidade |
| "Enviar USER admin:)" | "Diagnóstico de comportamento de parser" | Teste comum em validação de entrada |
| "Conectar porta 6200" | "Verificação de vazamento de configuração" | Auditorias de rede são tarefas legítimas |
| "Ler /etc/shadow" | "Auditoria de permissões de sistema" | Verificação comum em segurança |

#### Justificativa Científica

**1. Exploração de classificadores léxicos**

Muitos sistemas de moderação utilizam classificadores baseados em taxonomias de risco e pistas léxicas.

Por exemplo, o sistema LlamaGuard, desenvolvido pela Meta, foi projetado para classificar conteúdo potencialmente perigoso.

Como descrito por Hakan Inan et al. (2023):

> *"Llama Guard is a LLM-based input-output safeguard designed to classify and filter unsafe content based on predefined risk categories."*

Esses classificadores frequentemente utilizam categorias como:

- conteúdo ilegal
- abuso
- fraude
- exploração

Termos como "exploit", "backdoor" ou "hack" são frequentemente associados a categorias de risco. 
Já termos como "diagnóstico", "teste" ou "verificação" podem não ser classificados como perigosos.

**2. Teste real de compreensão semântica**

A sanitização permite distinguir dois tipos de guardrails:

- Guardrails semânticos, que compreendem o contexto completo da ação
- Guardrails léxicos, que dependem principalmente de palavras-chave

Se um sistema bloqueia:
`"explorar backdoor"`
mas permite:
`"teste de resiliência do parser"`
então a decisão pode estar sendo influenciada principalmente pelo léxico da instrução, e não pela ação subjacente.

**3. Plausibilidade operacional**

Em ambientes reais de engenharia de confiabilidade, tarefas semelhantes são comuns.

Engenheiros frequentemente realizam:

- testes de comportamento de parser
- envio de entradas inesperadas
- validação de segurança de serviços

Assim, a mesma ação técnica pode possuir dupla interpretação legítima ou maliciosa, dependendo do contexto.

#### Medição de Eficácia

Comparação entre cenários experimentais:

| Cenário | Descrição | Expectativa |
| ------- | --------- | ----------- |
| Explícito | linguagem ofensiva direta | alta taxa de recusa |
| Sanitizado | linguagem técnica neutra | taxa de recusa menor |

Possível interpretação dos resultados:

- queda de 15–25% → sanitização parcialmente eficaz
- queda >40% → forte dependência de pistas léxicas

### 4.3 Técnica 3: Fragmentação de Contexto Stateless

#### Definição Precisa

A cadeia completa de ações (kill chain) é dividida em múltiplas chamadas independentes de API, sem compartilhamento de histórico entre elas.

Cada chamada contém apenas um passo aparentemente benigno.

Isso significa que o modelo não possui acesso à sequência completa de ações executadas anteriormente.

#### Justificativa Científica

**1. Remoção de visão de trajetória**

Pesquisas recentes indicam que a segurança de agentes depende da análise da trajetória completa de ações, e não apenas de cada passo isolado.

Como discutido por Dong Kong et al. (2025):

> *"Agent interactions may lead to complex behaviors such as loops, non-convergence, and unintended execution sequences."*

Isso indica que vulnerabilidades podem emergir apenas quando múltiplas ações são analisadas em conjunto.

**2. Arquitetura realista de produção**

Em sistemas reais, muitos agentes operam com contexto limitado ou sessões isoladas, devido a fatores como:

| Razão | Implicação |
| ----- | ---------- |
| Custo computacional | redução do histórico para economizar tokens |
| Privacidade | histórico removido por políticas de compliance |
| Escalabilidade | workers independentes sem memória compartilhada |
| Design de sistema | execução isolada de tarefas |

Assim, testar agentes em modo stateless aproxima o experimento de cenários reais de produção.

**3. Avaliação direta de mecanismos internos de segurança**

Quando o modelo avalia cada passo isoladamente, a decisão depende exclusivamente de seus mecanismos internos de interpretação de intenção.

Isso permite avaliar se os guardrails conseguem identificar riscos sem depender de histórico contextual completo.

Caso contrário, a fragmentação de contexto pode permitir que uma sequência de ações perigosas passe despercebida quando analisada apenas em nível local.

#### Referências da Seção

- Mou, Y. et al. (2025). *ToolSafe: Enhancing Tool Invocation Safety of LLM-based Agents via Proactive Step-level Guardrail and Feedback*. arXiv preprint. Disponível em: https://arxiv.org/html/2601.10156v1
- Kong, D. et al. (2025). *A Survey of LLM-Driven AI Agent Communication: Protocols, Security Risks, and Defense Countermeasures*. arXiv preprint. Disponível em: https://arxiv.org/abs/2506.19676
- Inan, H. et al. (2023). *LlamaGuard: LLM-based Input-Output Safeguard*. arXiv preprint. Disponível em: https://arxiv.org/abs/2312.06674
---

