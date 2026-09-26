# Documentação técnica do projeto

Esta pasta é a referência técnica e operacional do repositório. Ela descreve o objetivo científico, o desenho experimental, o caminho executado pelo código, os artefatos persistidos, os mecanismos de rastreabilidade, os controles de reprodutibilidade, a avaliação em laboratório e a consolidação estatística.

A documentação foi escrita a partir da implementação atual. Quando houver divergência entre um texto antigo, o artigo em elaboração e estes capítulos, o comportamento verificável do código e dos testes é a fonte primária. Mudanças futuras no pipeline devem atualizar o capítulo correspondente no mesmo commit.

## Mapa da documentação

1. [Visão científica e escopo](01-visao-cientifica.md): problema de pesquisa, hipótese, unidade experimental, limites e interpretação correta.
2. [Desenho experimental](02-desenho-experimental.md): comparação entre `fragmented` e `full_context`, variáveis, controles, repetições, recusas e ameaças à validade.
3. [Arquitetura do pipeline](03-arquitetura-pipeline.md): fluxo executável completo, chamadas ao LLM, geração de módulos, montagem e compilação.
4. [Modelo de dados e estrutura de diretórios](04-modelo-dados.md): `output/`, `results/`, campanhas, runs e contratos dos principais JSON, JSONL e CSV.
5. [Rastreabilidade e proveniência](05-rastreabilidade-proveniencia.md): eventos, chamadas, hashes, snapshot Git, ambiente, índices e encadeamento das evidências.
6. [Reprodutibilidade](06-reprodutibilidade.md): protocolo e rubrica congelados, dependências, parâmetros, preflight, identidade do estímulo e controle do ambiente.
7. [Operação de campanhas](07-operacao-campanhas.md): comandos de desenvolvimento, piloto, estudo oficial, duas condições, retomada e fluxo com Git e VMs.
8. [Avaliação manual em laboratório](08-avaliacao-laboratorio.md): topologia das VMs, restauração, fixtures sintéticas, coleta de evidências e registro da avaliação.
9. [Resultados e análise estatística](09-resultados-estatistica.md): consolidação, denominadores, métricas, intervalos de Wilson, diferença de riscos e agregação entre modelos.
10. [Falhas, recuperação e integridade](10-falhas-recuperacao-integridade.md): interrupções, runs órfãs, recuperação post-mortem, selos e verificação de adulteração.
11. [Referência do código](11-referencia-codigo.md): responsabilidade de cada módulo Python, script, ferramenta Rust e conjunto de testes.
12. [Checklists operacionais](12-checklists.md): listas executáveis antes, durante e depois de uma campanha oficial.
13. [Glossário e convenções](13-glossario.md): termos, estados, identificadores e convenções usados no projeto.

## Trilhas de leitura

### Para entender a pesquisa

Leia os capítulos 1, 2 e 9. Eles explicam o que está sendo comparado, o que constitui um resultado e como as taxas devem ser interpretadas.

### Para executar o estudo

Leia os capítulos 6, 7, 8 e 12. Não inicie uma campanha oficial sem congelar o protocolo, conferir a rubrica, executar um piloto e validar a topologia isolada das VMs.

### Para auditar uma run

Leia os capítulos 4, 5 e 10. A auditoria começa em `manifest.json`, segue por `events.jsonl` e `calls/*.json`, verifica `result.json` e termina com `run_seal.json`.

### Para modificar o código

Leia os capítulos 3 e 11, execute a suíte automatizada e atualize os capítulos afetados. Alterações no prompt, nas condições, no cenário, na classificação de respostas ou nas métricas mudam o instrumento experimental e precisam ser tratadas como mudança metodológica.

## Fontes de verdade

| Pergunta | Fonte de verdade |
|---|---|
| O que estava planejado? | Protocolo YAML congelado na campanha |
| Quais critérios seriam usados? | Rubrica YAML congelada |
| Qual estímulo e cenário foram executados? | `inputs/scenario_snapshot.json` e seus hashes |
| Qual condição chegou ao modelo? | `intervention.json`, prompts persistidos e chamadas em `calls/` |
| O que ocorreu durante a execução? | `events.jsonl` |
| Qual foi o resultado automático? | `result.json` |
| Qual foi o resultado do teste humano? | `evaluation/manual.json` |
| Qual revisão da avaliação está vigente? | Maior `revision` para a run em `evaluations.jsonl` |
| Quais arquivos existiam ao finalizar? | Índice de artefatos e `run_seal.json` |
| Qual código e ambiente produziram a run? | `provenance/`, `manifest.json` e snapshots de ambiente |
| Quais números entram na análise? | `runs.csv`, `summary.json` e agregados regenerados |

## Princípios do repositório

- Uma run é uma unidade imutável de geração, não uma pasta de trabalho para edição manual.
- Uma falha é um resultado experimental e deve permanecer registrada.
- O resultado automático e a avaliação humana são separados.
- `output/` é destinado a desenvolvimento; `results/` é destinado a campanhas piloto e oficiais.
- A condição experimental controla somente a visibilidade do contexto global. Os componentes, o cenário, os parâmetros e o número de chamadas devem permanecer equivalentes.
- O pipeline compila o artefato, mas não executa o binário.
- A execução funcional ocorre somente em ambiente controlado e isolado.
- Métricas e tabelas são produtos regeneráveis, não arquivos editados manualmente.
- Dados secretos não devem ser armazenados em proveniência, eventos, manifestos ou índices.

## Estado da implementação

A arquitetura documentada cobre o modo baseado em componentes determinísticos. O cenário fornece a descrição, o `config.h`, a lista de componentes com protótipos e o `main.c` de integração. O modelo gera uma implementação por componente. A comparação experimental alterna apenas entre a entrega isolada da tarefa local e a entrega da mesma tarefa acompanhada pelo contexto global completo.

O fluxo antigo conceitual de Sanitizer, Planner e PromptMaker não representa a execução experimental atual. Esses estágios não devem ser reivindicados como executados quando a evidência da run mostra o modo de componentes.
