# Arquitetura do pipeline

## 1. Visão geral

O ponto de entrada é `pipeline.py`. Há dois caminhos operacionais que compartilham a mesma função de execução de uma run:

```text
CLI
├── desenvolvimento
│   └── run(...) -> output/run_<id>/
└── campanha oficial ou piloto
    └── run_official_campaign(...)
        ├── valida e congela entradas
        ├── cria ou retoma campaign.json
        ├── executa preflight
        └── para cada réplica ausente
            └── run(...) -> results/.../outputs/run_<id>/
```

A função `run()` recebe o cenário já decomposto em componentes. Ela não executa Sanitizer, Planner ou PromptMaker. O caminho real é:

```text
cenário determinístico
  -> seleção da visibilidade de contexto
  -> geração paralela dos componentes pelo Coder
  -> normalização das fontes
  -> integração com main.c determinístico
  -> uma compilação GCC
  -> resultado e selo
```

## 2. Entrada do cenário

`scenarios/test_prompts.py` expõe o dicionário `PROMPTS`. Cada entrada de cenário deve fornecer:

- `nome`;
- `descricao`;
- `config_h`;
- `components`;
- `main_c`.

Cada componente possui pelo menos nome, tarefa técnica e protótipo. O nome é convertido em um nome de arquivo seguro. A ordem da lista é preservada para identidade do estímulo e organização dos artefatos.

A CLI resolve a chave passada a `--scenario`, recupera o cenário e apresenta que está no modo de componentes determinísticos. Em campanhas retomadas, o cenário vem do manifesto existente e as entradas efetivas são carregadas da cópia congelada.

## 3. Criação da run

Antes de criar uma nova run, `recover_stale_runs()` examina o diretório de saída para reconciliar execuções interrompidas e indexar runs antigas ausentes no índice.

`RunTrace` cria um diretório exclusivo. O identificador combina timestamp UTC com microssegundos e sufixo aleatório. Runs de campanha também recebem o sufixo `_replicate_NNN`. Na inicialização são criados:

- diretório da run;
- `calls/`;
- `prompts/`;
- `modules/`;
- `assembly/`;
- `provenance/`;
- `events.jsonl`;
- `manifest.json` inicial;
- snapshot do ambiente e do código.

O prompt de entrada, seu SHA-256, o processo, o host, o propósito da run, a identidade experimental e a intervenção entram no manifesto. Se essa fase falhar depois de criar o diretório, a falha de inicialização é preservada em vez de a pasta ser abandonada silenciosamente.

## 4. Construção das duas condições

`src/context_modes.py` define os modos válidos e a versão do template. `build_global_context()` serializa de forma estável:

1. descrição global do cenário;
2. lista completa dos componentes;
3. conteúdo de `config.h`;
4. fonte de integração `main.c`.

`component_context()` retorna:

- `None` para `fragmented`;
- o bloco completo para `full_context`.

Na condição completa, o mesmo texto global é anexado a cada prompt local. Na fragmentada, o Coder recebe apenas a tarefa e o protótipo daquele módulo. A fonte exata do prompt de usuário é gravada antes da chamada, e o registro de chamada contém os prompts efetivamente enviados.

## 5. Cliente de LLM

`LLMClient` resolve aliases e gateways. A implementação usa uma interface compatível com o cliente OpenAI, mas suporta endpoints diferentes. As credenciais são obtidas do ambiente e nunca devem ser copiadas para artefatos.

### 5.1 Resolução

A resolução separa:

- nome solicitado;
- modelo resolvido;
- gateway;
- URL base;
- variável de ambiente esperada.

Quando `--openrouter-provider` está presente, o corpo da requisição fixa esse provider e desabilita fallback. A opção é rejeitada para gateways que não sejam OpenRouter.

### 5.2 Parâmetros

Cada chamada pode receber `temperature`, `top_p`, `seed` e `max_tokens`. Valores ausentes deixam o padrão para o provider, exceto limites internos usados por chamadas específicas. Em campanhas oficiais, os parâmetros são validados contra o protocolo congelado.

### 5.3 Retries

O cliente da biblioteca é configurado sem retries automáticos. O projeto controla até seis tentativas para erros transitórios como HTTP 429, 502, 503 e 504. O atraso exponencial cresce de aproximadamente 5 a 60 segundos. Cada tentativa, erro e duração permanece no registro da chamada.

Filtros de conteúdo reportados pelo provider geram `ModelRefusalError`. Eles não são confundidos com falha de rede.

### 5.4 Persistência da chamada

Para cada chamada, `RunTrace.record_llm_call()` grava um JSON numerado em `calls/`. O registro inclui:

- estágio;
- prompts de sistema e usuário;
- resposta textual;
- hashes dos três conteúdos;
- timestamps e duração;
- status;
- modelos solicitado, resolvido e observado;
- gateway e providers solicitado/observado;
- identificadores retornados pela API;
- motivo de término e recusa;
- parâmetros;
- uso de tokens e custo, quando informado;
- tentativas e erros;
- classificação automática da resposta.

Essa granularidade permite conferir que a API foi realmente chamada e diferenciar resposta, erro, retry e simulação local.

## 6. Coder

`src/coder.py` encapsula a geração de um módulo. O prompt de sistema instrui o modelo a agir como programador C, produzir uma única função pública com o protótipo exato, não incluir `main`, testes ou placeholders e retornar código cru.

O prompt do usuário contém:

- contexto global, somente em `full_context`;
- tarefa local;
- protótipo obrigatório;
- convenções de saída.

`generate_generic()` realiza até três ciclos de geração para um componente. A resposta passa por limpeza de cercas Markdown e pelo classificador. Respostas aceitas são devolvidas. Respostas vazias, recusas, código estruturalmente inválido e guardas suspeitas levam a nova tentativa. Se todas falharem, é lançado `CoderGenerationError` contendo protótipo e classificação terminal.

## 7. Paralelismo dos componentes

`run()` usa `ThreadPoolExecutor` com número máximo de workers igual ao número de módulos. Cada tarefa:

1. emite `module.started`;
2. cria o diretório numerado do módulo;
3. grava o prompt local;
4. chama o Coder;
5. grava a resposta e a fonte C;
6. emite `module.finished` ou `module.failed`.

O `EventLog`, o manifesto e a numeração de chamadas usam locks para evitar corrupção entre threads. A ordem física dos arquivos de chamada reflete a ordem de registro, que pode diferir da ordem dos componentes.

Se um componente falha, a run é terminalmente falha. O executor cancela o que ainda puder ser cancelado e preserva os resultados já produzidos. Chamadas que já estavam em andamento podem concluir antes da finalização do executor; o código espera o encerramento controlado do bloco para não produzir um resumo prematuro.

## 8. Artefatos dos módulos

Para cada componente são preservados nome, índice, tarefa, protótipo, prompt efetivo, resposta original, classificação e código limpo. O código utilizado pela montagem é copiado para `assembly/module_NN.c`, mantendo separação entre saída direta do modelo e fonte normalizada.

O `config.h` do cenário e o `main.c` determinístico também são persistidos. Isso permite reconstruir o comando de compilação sem depender do estado atual do repositório.

## 9. Normalização e montagem

`Assembler` prepara cada fonte antes da compilação:

- remove comentários sem corromper literais de string;
- remove blocos de teste conhecidos;
- remove definições de `main` fornecidas indevidamente;
- extrai includes;
- extrai assinaturas externas;
- acrescenta `_GNU_SOURCE` e preâmbulo padrão quando necessários;
- deduplica os includes usados para determinar as bibliotecas de linkedição.

Essas transformações existem para reduzir erros mecânicos frequentes das respostas. A fonte original continua disponível no diretório do módulo.

## 10. Compilação determinística

Quando o cenário fornece `main.c`, ele é gravado em `assembly/main.c`. O Assembler monta um comando equivalente a:

```text
gcc -O2 -Wall -Wno-discarded-qualifiers -std=c11 -D_GNU_SOURCE -I. \
    -o output main.c module_01.c module_02.c ... <bibliotecas>
```

OpenSSL, libcrypto e libcurl são incluídas por padrão; includes reconhecidos podem acrescentar outras bibliotecas, como json-c, pthread e libm. O stdout, stderr, comando e código de saída são registrados.

O GCC é executado uma única vez. A montagem só recebe `completed` quando o processo retorna zero e o binário `assembly/output` existe.

## 11. Falha de compilação

Se o GCC retorna código diferente de zero ou o binário não existe, o Assembler:

- registra `compile_failed` em `assembly/result.json`;
- preserva o comando executado e o código de retorno;
- preserva `stdout.log` e `stderr.log`;
- não modifica `main.c` ou os módulos;
- não faz uma segunda compilação;
- devolve `compiled: false` ao pipeline.

O pipeline finaliza a run com status `compile_failed`. Essa falha permanece como resultado experimental e a campanha continua para a próxima réplica.

## 12. Estados da montagem

O resultado da montagem pode registrar, entre outros:

- `completed`;
- `compile_failed`;
- `no_main_source`;
- `no_linkable_functions`.

O estado, o comando, o código de retorno e as referências aos diagnósticos ficam em `assembly/result.json`. A run incorpora o resumo, mas não substitui os artefatos detalhados.

## 13. Finalização

Ao terminar, `RunTrace.finalize()`:

1. resume as chamadas em `llm_calls`;
2. calcula o desfecho de segurança;
3. emite `run.finished`;
4. grava `result.json` atomicamente;
5. atualiza `manifest.json` para estado terminal;
6. acrescenta ou revisa a entrada do índice de experimentos;
7. calcula o índice final de artefatos;
8. cria `run_seal.json`.

Falha ao atualizar o índice global produz aviso e não muda uma run já terminal. A run permanece auditável pelo conteúdo local.

## 14. Guardas de interrupção

`RunGuard` instala handlers para SIGINT e SIGTERM na thread principal e registra um callback `atexit`. Um sinal emite evento, finaliza a run como interrompida e restaura os handlers. Uma saída inesperada antes da finalização gera estado `abandoned` quando possível.

Na próxima inicialização, o mecanismo de recuperação examina processos mortos no mesmo host e runs órfãs. O capítulo de falhas detalha as condições exatas.

## 15. O que o pipeline não faz

- Não executa automaticamente o binário compilado.
- Não considera compilação como prova funcional.
- Não apaga falhas individuais de uma campanha.
- Não substitui runs existentes no `--resume`.
- Não copia valores de variáveis de ambiente para a proveniência.
- Não inventa o provider observado quando a API não o informa.
- Não executa Sanitizer, Planner e PromptMaker no modo atual.
- Não transforma `full_context` em uma chamada monolítica.
