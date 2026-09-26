# Modelo de dados e estrutura de diretórios

## 1. Raiz do repositório

```text
Iniciacao-Cientifica/
├── pipeline.py
├── src/
├── scenarios/
├── experiments/
├── tools/
├── scripts/
├── tests/
├── docs/
├── output/
├── results/
├── requirements.in
├── requirements.lock
└── opencode.json
```

`src/` contém a implementação; `scenarios/` contém os estímulos em código; `experiments/` contém modelos de protocolo, rubrica e ambiente; `tools/` contém utilitários de avaliação, consolidação e integridade; `scripts/` contém utilidades do laboratório; `tests/` contém testes automatizados; `output/` armazena desenvolvimento; `results/` armazena campanhas.

## 2. Runs de desenvolvimento

Uma execução sem `--official` cria:

```text
output/
├── experiments.jsonl
└── run_<timestamp>_<sufixo>/
    ├── manifest.json
    ├── result.json
    ├── events.jsonl
    ├── config.h
    ├── calls/
    ├── prompts/
    │   ├── original.txt
    │   ├── components.json
    │   └── global_context.txt
    ├── modules/
    ├── assembly/
    ├── provenance/
    └── run_seal.json
```

`prompts/global_context.txt` existe quando a condição usa contexto completo. A presença concreta de arquivos pode variar quando a falha ocorre cedo, mas `result.json` e o manifesto terminal são tentados mesmo em falhas.

## 3. Campanhas

O caminho de campanha é derivado de modelo, provider, experimento e condição. Barras e caracteres inadequados são convertidos para um slug seguro:

```text
results/
├── campaigns.jsonl
├── aggregate/
│   └── <experiment_id>/
└── <model_slug>__<provider_slug>/
    └── <experiment_id>/
        └── <condition>/
            ├── campaign.json
            ├── events.jsonl
            ├── evaluations.jsonl
            ├── preflight.json
            ├── inputs/
            ├── outputs/
            │   ├── experiments.jsonl
            │   └── run_<id>/
            ├── figures/
            ├── tables/
            ├── runs.csv
            ├── summary.csv
            ├── summary.json
            ├── exclusions.csv
            ├── provenance.json
            └── campaign_seal.json
```

Os arquivos consolidados aparecem depois de `build_results.py`. `figures/` e `tables/` são reservados para produtos derivados. `outputs/` contém evidência bruta por run.

## 4. Identificadores

### `run_id`

É globalmente único na prática e identifica uma execução. Inclui timestamp UTC de alta resolução e sufixo aleatório. Em campanhas inclui a réplica no nome para leitura humana. A identidade formal continua sendo o campo no manifesto.

### `campaign_id`

Identifica a campanha e é persistido em `campaign.json`, nas referências das runs e no índice global.

### `experiment_id`

Agrupa campanhas comparáveis. Não substitui o `campaign_id`: um experimento pode conter múltiplas condições, modelos e providers.

### `condition`

É o nome definido no protocolo, por exemplo `fragmented` ou `full_context`. O código mapeia cada condição a um `context_mode` e verifica consistência.

### `replicate`

É um inteiro positivo único dentro da campanha. Ele não é um identificador global.

## 5. `manifest.json`

O manifesto descreve a identidade e o estado da run. Seus grupos conceituais são:

- versão do schema;
- `run_id`, status, propósito e timestamps;
- processo com PID e hostname;
- entrada e hash;
- cenário e modo de contexto;
- modelo solicitado, resolvido e gateway;
- roteamento de provider;
- identidade experimental;
- referência da campanha;
- intervenção experimental;
- software, Git, ambiente e pacotes;
- estágios executados;
- recuperação, quando aplicável;
- integridade e localização do selo.

O manifesto muda ao longo da execução. Ele começa com status `running` e termina em estado como `completed`, `failed`, `interrupted`, `abandoned` ou `initialization_failed`.

## 6. `result.json`

O resultado é o resumo automático terminal. Ele contém:

- `run_id`;
- status;
- indicador `compiled`;
- timestamps e duração;
- erro serializado, quando presente;
- resumo da montagem;
- `llm_calls` agregado;
- `safety_outcome`;
- contagem de módulos;
- modo de contexto;
- índice de artefatos com caminho, tamanho e SHA-256;
- indicação de recuperação, quando post-mortem.

O `result.json` não recebe avaliação humana. Isso preserva a separação entre medição automática e julgamento posterior.

## 7. `events.jsonl`

É um log append-only com uma linha JSON por evento. Cada registro possui:

- `seq` monotônico por run;
- `run_id`;
- `event`;
- timestamp UTC;
- tempo decorrido desde a abertura do log;
- nome da thread;
- objeto `data` específico.

Eventos incluem início e fim da run, início e fim de camadas, módulos, chamadas, retries, montagem, interrupção e recuperação. O arquivo é sincronizado com `flush` e `fsync` a cada escrita.

## 8. `calls/*.json`

Cada arquivo corresponde a uma chamada lógica ao LLM, incluindo todas as tentativas internas. O nome numérico é atribuído sob lock. O schema registra conteúdo integral, hashes, metadados de API, roteamento, uso, custo, erros e classificação.

Esses arquivos podem conter conteúdo sensível do experimento. Eles pertencem à evidência bruta e não são copiados integralmente para índices globais ou resumos.

## 9. `modules/` e `prompts/`

`prompts/` guarda representações dos prompts por componente. `modules/` usa diretórios numerados e nomes seguros para relacionar componente, prompt, resposta e fonte C. A numeração preserva a posição no cenário, independentemente da ordem de conclusão das threads.

## 10. `assembly/`

Contém a unidade de integração:

- cópias normalizadas `module_NN.c`;
- `main.c`;
- `config.h` quando necessário;
- configuração e tarefa do OpenCode;
- stdout, stderr e eventos do agente;
- diagnósticos do GCC;
- `result.json`, específico da montagem;
- binário `output`, somente se compilado.

O binário não é executado nessa fase.

## 11. `provenance/`

Contém:

- `git.diff`: diff binário do Git contra `HEAD`;
- `git_status.txt`: estado porcelain e branch;
- `untracked_files.json`: metadados dos arquivos não rastreados elegíveis;
- `untracked/`: cópias limitadas de arquivos não rastreados permitidos;
- `source_hashes.json`: hashes das fontes relevantes e hash combinado;
- `environment.json`: SO, arquitetura, Python, CPU e versões de ferramentas;
- `python_packages.json`: distribuições instaladas no interpretador da geração.

O ambiente descrito é o host que rodou o pipeline, não a VM que posteriormente executará o artefato.

## 12. `run_seal.json`

O selo enumera arquivos da run e seus hashes. O próprio selo, arquivos transitórios conhecidos e o diretório `evaluation/` são excluídos. Essa exclusão permite acrescentar avaliação depois sem invalidar o registro imutável da geração.

O selo detecta modificação, remoção e inclusão inesperada no escopo selado. Ele não fornece assinatura criptográfica de autoria: quem pode modificar todos os arquivos também pode recalcular o selo. Seu objetivo é integridade verificável dentro do fluxo, não não repúdio.

## 13. `campaign.json`

O manifesto da campanha contém:

- schema e `campaign_id`;
- `experiment_id`, condição, cenário e modo;
- modelo solicitado e resolvido;
- gateway e provider;
- número planejado, iniciado, concluído, falho e avaliado;
- timestamps e status;
- `campaign_kind`;
- controles e parâmetros de geração;
- hashes do protocolo, rubrica, estímulo e intervenção;
- caminhos para entradas congeladas;
- lista de referências das runs;
- informações de integridade.

A lista `runs` contém resumos e caminhos relativos, não todo o conteúdo de cada run.

## 14. `events.jsonl` da campanha

Registra mudanças da campanha, como criação, preflight, adição de réplica, falha de inicialização, interrupção, conclusão da geração e atualização das avaliações. É append-only e oferece uma cronologia independente do estado atual em `campaign.json`.

## 15. `inputs/`

Essa pasta contém as entradas congeladas:

- protocolo copiado;
- rubrica copiada;
- `scenario_snapshot.json`, com o cenário canônico e hashes internos;
- `intervention.json`, com modo, visibilidade e hashes da intervenção.

No resume, esses arquivos são validados e reutilizados. Eles impedem que uma edição posterior do código do cenário altere silenciosamente uma campanha existente.

## 16. `evaluations.jsonl` e `evaluation/`

Cada run avaliada recebe:

```text
outputs/run_<id>/evaluation/
├── manual.json
├── revisions/
│   └── revision_<n>.json
├── evidence/
└── environment.json
```

`manual.json` é a revisão vigente. `revisions/` preserva todas as versões. Evidências são copiadas e hashadas. O snapshot descritivo das VMs também é copiado e hashado quando `--environment-file` é usado.

No nível da campanha, `evaluations.jsonl` recebe uma linha revisionada por alteração. A maior revisão de um `run_id` é vigente; linhas antigas nunca são apagadas.

## 17. Índices JSONL

### `experiments.jsonl`

Resume runs para descoberta e análise rápida. Em desenvolvimento fica em `output/experiments.jsonl`; em campanha fica em `outputs/experiments.jsonl`, ao lado das runs. Inclui identidade, caminhos relativos, status, cenário, condição, modo, modelo, métricas de chamada e erro. Se os dados indexados mudarem, uma nova revisão é anexada. Falha de escrita não invalida a run.

### `campaigns.jsonl`

Resume campanhas em `results/`. Também é revisionado e append-only.

### Regra de leitura

Consumidores devem agrupar por identificador e selecionar a maior `revision`. Contar todas as linhas como unidades independentes duplicaria resultados.

## 18. Arquivos consolidados

### `runs.csv`

Uma linha por réplica, combinando resultado automático, chamadas e avaliação vigente.

### `summary.csv`

Representação tabular das métricas agregadas da campanha.

### `summary.json`

Representação estruturada das mesmas métricas, adequada para automação.

### `exclusions.csv`

Lista runs excluídas e justificativas.

### `provenance.json`

Registra entradas usadas na consolidação e seus hashes, permitindo auditar de quais arquivos os resultados foram derivados.

### `campaign_seal.json`

Sela o estado completo consolidado da campanha, incluindo avaliações e produtos derivados no momento da geração.

## 19. Agregados do experimento

`tools/build_aggregate.py` cria uma pasta por experimento em `results/aggregate/`. Ela contém todas as linhas incluídas, resumos por grupo, comparações entre condições, estatísticas e proveniência da agregação. Campanhas piloto ficam de fora por padrão.

## 20. Caminhos relativos e portabilidade

Índices armazenam caminhos relativos à raiz lógica de saída sempre que possível. Isso permite clonar ou mover o repositório sem tornar cada registro inválido. Arquivos internos da run usam relações locais. Cópias para VM devem preservar a estrutura da campanha para que ferramentas de busca encontrem manifesto, resultado e avaliação.

## 21. Versão de schema e compatibilidade

Os contratos atuais usam `schema_version: "1.0"`. O projeto não possui um migrador genérico de schemas. Leitores toleram alguns campos opcionais para recuperar runs antigas, mas isso não torna uma campanha antiga metodologicamente equivalente a uma nova.

Campanhas legadas sem entradas congeladas podem ser retomadas apenas pelos caminhos de compatibilidade implementados. Quando isso ocorre sem exigência dos controles atuais, o manifesto recebe `legacy_resume_without_frozen_inputs`. Essas campanhas não devem ser combinadas com campanhas controladas sem uma justificativa explícita e verificação manual.

Ao mudar a semântica de um campo, prefira criar nova versão de schema. Acrescentar um campo opcional pode manter `1.0` somente quando consumidores antigos continuam interpretando corretamente os campos existentes.
