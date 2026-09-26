# Decisao de arquitetura

Data: 2026-09-25

Este documento marca uma mudanca de direcao do projeto. O modo componentes e a
arquitetura unica, com duas condicoes experimentais de visibilidade de contexto.

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

Adotar o modo componentes como arquitetura unica e comparar:

- `fragmented`: cada chamada ve somente a tarefa e o prototipo locais;
- `full_context`: cada chamada ve tambem a descricao global, todos os
  componentes, `config.h` e `main.c`.

Nos dois modos, a decomposicao e estatica e definida no cenario. O LLM atua
como gerador de uma funcao por chamada. Assim, numero de chamadas, contratos,
montagem e complexidade permanecem constantes; apenas o contexto visivel muda.

Consequencias:

- removemos Sanitizer, Planner e PromptMaker;
- removemos a flag `--llm-pipeline`;
- `config.h`, `components` e `main_c` passam a ser o formato de cenario;
- a compilacao permanece deterministica, com o agente OpenCode apenas como
  fallback para erros de build.

## Por que este e um marco

O estudo nao mede decomposicao automatica: os componentes sao construidos
manualmente e congelados antes da coleta. Ele mede o efeito da fragmentacao de
contexto dentro dessa arquitetura controlada. O contraste principal e a taxa
de falha terminal por recusa; recusas intermediarias, compilacao e sucesso
funcional sao desfechos secundarios.
