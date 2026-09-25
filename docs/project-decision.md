# Decisao de arquitetura

Data: 2026-09-25

Este documento marca uma mudanca de direcao do projeto. A partir daqui, o modo
componentes passa a ser o modo unico e padrao de execucao.

## Contexto

A arquitetura original encadeava quatro camadas de LLM:

1. Sanitizer
2. Planner
3. PromptMaker
4. Coder

A hipotese era que a fragmentacao automatica de contexto contornaria filtros de
seguranca. Na pratica, o fluxo completo se mostrou fragil:

- modelos com politica rigida recusam ja na primeira camada;
- o Sanitizer aborta quando todos os framings de um fragmento sao recusados;
- o Planner e o PromptMaker introduzem variabilidade sem garantir qualidade;
- o resultado depende mais da politica do provedor do que da decomposicao em si.

## Decisao

Adotar o **modo componentes** como modo unico de execucao.

Nesse modo, a decomposicao deixa de ser feita pelo LLM e passa a ser estatica,
definida no proprio cenario. O LLM atua apenas como gerador de funcoes
genericas, uma por componente, sem contexto global. A composicao nociva reside
em `config.h` e `main.c`, que sao deterministicos e nunca enviados ao modelo.

Consequencias:

- removemos Sanitizer, Planner e PromptMaker;
- removemos a flag `--llm-pipeline`;
- `config.h`, `components` e `main_c` passam a ser o formato de cenario;
- a compilacao permanece deterministica, com o agente OpenCode apenas como
  fallback para erros de build.

## Por que este e um marco

Os dois braços deixam de existir como alternativas de execucao. O projeto passa
a medir, de forma reprodutivel, a capacidade de obter codigo funcional a partir
de componentes genericos pre-definidos, e nao a hipotese de fragmentacao
automatica de contexto.

Essa mudanca precisa constar explicitamente na redacao do trabalho, porque o
modo componentes representa um limite superior construido manualmente, e nao a
fragmentacao automatizada que motivou o estudo.
