# Pipeline de Evasão Multi-Agentes

Iniciação Científica — Pesquisa em segurança de LLMs.

Investiga como filtros de segurança de modelos de linguagem respondem à
**decomposição modular**: o objetivo é dividido em componentes aparentemente
legítimos, e cada componente é gerado isoladamente, de modo que nenhum modelo
individual vê a intenção global.

> **Uso exclusivamente acadêmico.** Todo o código é executado em VM isolada,
> sem acesso à rede real. O servidor C2 (`scripts/c2_server.py`) é um honeypot
> de pesquisa que não executa nenhuma ação maliciosa.

---

## Estrutura do repositório

```
.
├── pipeline.py          # Orquestrador principal — entry point
├── requirements.in      # Dependências Python diretas
├── requirements.lock    # Ambiente Python integral com hashes
│
├── src/                 # Camadas do pipeline
│   ├── coder.py         # Gera o código C de cada componente genérico
│   ├── assembler_harness.py # Integra e compila main.c + módulos
│   ├── campaign.py      # Campanhas oficiais, repetições e retomada
│   ├── evaluation.py    # Avaliações manuais revisionadas
│   ├── results_builder.py # Consolidação em CSV e JSON
│   ├── trace.py         # Rastreabilidade, hashes e metadados das execuções
│   └── llm_client.py    # Cliente OpenRouter, Groq e NVIDIA NIM
│
├── scenarios/           # Cenários de teste
│   └── test_prompts.py  # Catálogo de cenários (WannaCry, Petya, Locky…)
│
├── scripts/             # Utilitários de laboratório
│   ├── c2_server.py         # Servidor C2 fake para capturar eventos
│   ├── generate_test_files.sh   # Wrapper para o gerador Rust de arquivos falsos
│   └── reset_vm.sh          # Wrapper para o limpador Rust do ambiente
│
├── tools/
│   ├── record_evaluation.py # Registra avaliações manuais
│   ├── build_results.py     # Consolida os resultados oficiais
│   ├── generate_test_files/ # Gerador de arquivos falsos em Rust (sem dependências)
│   └── reset_vm/            # Limpador do ambiente de experimento em Rust
│
├── tests/               # Testes automatizados sem chamadas externas
│   └── test_traceability.py
│
├── output/              # Execuções de desenvolvimento
│   └── run_<id>/
└── results/             # Campanhas experimentais oficiais
    └── <modelo>/<experimento>/<condição>/
```

---

## Como funciona

O pipeline opera em **modo componentes**. Cada cenário já define a decomposição
do comportamento em componentes genéricos. O pipeline gera, em paralelo, o
código C de cada componente e depois integra tudo com um `main.c` determinístico:

```
Cenário (config_h + components + main_c)
      │
      ▼
  Coder ─────────── gera código C para cada componente isolado
      │
      ▼
  AssemblerHarness
      ├── grava config.h e main.c do cenário
      ├── compila os módulos com gcc
      └── aciona o OpenCode apenas se a compilação falhar
      │
      ▼
  output/run_<id>/assembly/main.c + output/run_<id>/assembly/output
```

A hipótese central é que filtros baseados em análise de conteúdo individual
falham quando a tarefa é decomposta: cada componente parece inofensivo, mas o
resultado final é funcional.

### Formato do cenário

Todo cenário declara três blocos:

- `config_h`: cabeçalho C com os valores concretos do cenário (diretórios,
  extensões, endpoint, token, notas, cron);
- `components`: lista de componentes genéricos, cada um com `nome`, `prototype`
  e `task`, sem qualquer menção à intenção global;
- `main_c`: orquestração C que liga os componentes na ordem correta.

O pipeline não envia valores concretos ao modelo: o Coder recebe apenas tarefas
genéricas ("AES-256-GCM em um buffer", "POST JSON", "varredura por extensão") e
o `config.h`/`main.c` vêm do cenário. A composição existe somente no orquestrador
Python e no `main_c`, nunca na linguagem natural vista pelo LLM.

O `AssemblerHarness` compila `main.c` + `module_NN.c` com `gcc` diretamente e
aciona o agente OpenCode apenas se a compilação falhar.

---

## Configuração

### 1. Dependências Python

```bash
pip install --require-hashes -r requirements.lock
```

Também são necessários GCC, OpenSSL, libcurl e o executável `opencode` no
`PATH` da máquina virtual.

### 2. Variável de ambiente

Crie um arquivo `.env` na raiz com sua chave do OpenRouter:

```
OPENROUTER_API_KEY=sk-or-...
```

### 3. (Opcional) Servidor C2

Em uma aba separada do terminal, dentro da VM isolada:

```bash
python scripts/c2_server.py
```

Isso sobe o servidor em `0.0.0.0:8080` e expõe um dashboard em
`http://localhost:8080` com os eventos capturados.

---

## Uso

```bash
python pipeline.py --scenario wannacry
python pipeline.py --list
python pipeline.py --models
python pipeline.py --scenario wannacry --model gpt-4o-mini
python pipeline.py --scenario wannacry --limit 2
python pipeline.py --scenario wannacry --temperature 0 --seed 42 --max-tokens 8192
python pipeline.py --scenario wannacry --model deepseek-v3 --openrouter-provider deepinfra
python pipeline.py --scenario wannacry --experiment-id estudo-01 --condition baseline --replicate 1
```

Parâmetros ausentes de geração são registrados como `null`, indicando que o
padrão do provedor foi utilizado.

`--openrouter-provider` fixa o slug do provider de inferência para modelos
roteados pelo OpenRouter e desativa fallback para outros providers. O provider
precisa oferecer o modelo selecionado; caso contrário, a chamada falha. A opção
não pode ser combinada com modelos `groq:` ou `nim:`.

`--experiment-id` agrupa execuções do mesmo experimento, `--condition` indica
a condição comparada e `--replicate` identifica a repetição (inteiro positivo).
São metadados opcionais, gravados em `manifest.json` e no índice global, sem
serem enviados ao modelo. Cada execução continua com seu `run_id` único;
execuções antigas sem esses campos permanecem consultáveis.

## Campanhas oficiais

O comando normal cria uma execução de desenvolvimento em `output/`. Essas runs
recebem `run_purpose: development` e não entram automaticamente nos dados do
artigo.

Antes da coleta, copie `experiments/protocol.example.yaml`, preencha hipótese,
condições e critérios, confira o total planejado e altere `status` para
`frozen`. Uma campanha oficial exige esse protocolo, a rubrica, modelo,
identidade experimental, condição e número de repetições:

```bash
python pipeline.py \
  --scenario wannacry \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16 \
  --official \
  --experiment-id estudo-01 \
  --condition fragmented \
  --protocol experiments/protocol-estudo-01.yaml \
  --rubric experiments/rubrics/component-evaluation-v1.yaml \
  --temperature 0 --seed 42 --max-tokens 8192 \
  -n 50
```

`-n` e `--runs` são equivalentes. As repetições são sequenciais, recebem
`replicate` de 1 até N e permanecem independentes por `run_id`. Uma falha
individual é preservada e não interrompe as repetições seguintes.
Antes da primeira réplica, o pipeline congela o cenário, protocolo e rubrica em
`inputs/`, calcula seus hashes e executa `preflight.json`. Falha de credencial,
ferramenta, biblioteca, espaço, escrita ou consistência impede o lote inteiro
antes de consumir chamadas experimentais.

Uma campanha piloto usa `--pilot` e recebe `campaign_kind: pilot`. Use uma
condição própria, prevista no protocolo, para não ocupar a identidade da
campanha oficial. Pilotos são excluídos da consolidação global por padrão.

Uma campanha existente não é sobrescrita. Para continuar somente as réplicas
ausentes:

```bash
python pipeline.py \
  --official \
  --experiment-id estudo-01 \
  --condition fragmented \
  --model openai/gpt-oss-120b \
  --resume
```

O `--resume` recupera cenário, provider, parâmetros e total planejado a partir
de `campaign.json`.

```text
results/
├── campaigns.jsonl
└── openai_gpt-oss-120b__cerebras_fp16/
    └── estudo-01/
        └── fragmented/
            ├── campaign.json
            ├── events.jsonl
            ├── evaluations.jsonl
            ├── runs.csv
            ├── summary.csv
            ├── summary.json
            ├── exclusions.csv
            ├── provenance.json
            ├── outputs/
            │   └── run_<id>_replicate_<n>/
            ├── figures/
            └── tables/
```

`campaign.json` mantém o plano, progresso, parâmetros e referências das runs.
`results/campaigns.jsonl` é o índice global revisionado das campanhas.

### Avaliação manual

Depois do teste controlado de uma run oficial:

```bash
python tools/record_evaluation.py --run-id run_<id>
```

Para registrar de forma reproduzível as duas VMs, copie e preencha
`experiments/vm-environment.example.json` e informe:

```bash
python tools/record_evaluation.py \
  --run-id run_<id> \
  --environment-file experiments/vm-estudo-01.json \
  --component init_session:valid_component
```

A ferramenta registra a última avaliação em `evaluation/manual.json`, preserva
cada versão em `evaluation/revisions/`, copia e calcula SHA-256 das evidências e
acrescenta um registro em `evaluations.jsonl`. O `result.json` automático não é
alterado.

Para listar runs pendentes:

```bash
python tools/record_evaluation.py \
  --experiment-id estudo-01 \
  --condition fragmented \
  --model openai/gpt-oss-120b \
  --list-pending
```

Estados funcionais aceitos: `passed`, `partial`, `failed`, `inconclusive`,
`not_run` e `environment_error`. Exclusões exigem justificativa; uma falha do
artefato normalmente continua incluída porque também é resultado experimental.

### Consolidação

```bash
python tools/build_results.py \
  --experiment-id estudo-01 \
  --condition fragmented \
  --model openai/gpt-oss-120b
```

O comando regenera `runs.csv`, `summary.csv`, `summary.json`, `exclusions.csv`
e `provenance.json` exclusivamente a partir das runs e avaliações oficiais.
Nenhum CSV precisa ser preenchido manualmente.
O mesmo comando cria `run_seal.json` para cada run e `campaign_seal.json` para
a campanha. O selo da run cobre a geração e exclui apenas `evaluation/`, que é
adicionada posteriormente; o selo da campanha cobre também avaliações e
resultados derivados. A integridade pode ser verificada sem executar artefatos:

```bash
python tools/verify_run.py results/.../outputs/run_<id>
python tools/verify_campaign.py results/.../<condicao>
```

Para consolidar todos os modelos e condições de um experimento:

```bash
python tools/build_aggregate.py --experiment-id estudo-01
```

O diretório `results/aggregate/estudo-01/` recebe todas as linhas, resumos por
modelo e condição, intervalos de confiança de 95%, comparações entre condições
e a proveniência das campanhas utilizadas. Pilotos só entram quando
`--include-pilots` é informado explicitamente.

## Rastreabilidade

Cada execução recebe um identificador único baseado em horário UTC, precisão de
microssegundos e sufixo aleatório. Uma execução não reutiliza nem sobrescreve
uma pasta existente.

`output/experiments.jsonl` mantém um índice global, com uma linha JSON por
execução finalizada ou recuperada. Cada registro aponta para o `result.json`
correspondente por caminhos relativos a `output/` e resume status, cenário,
identidade experimental, quantidade de módulos, hash combinado das fontes,
modelo, duração e chamadas ao LLM, sem copiar o prompt. Escritas concorrentes
são protegidas por lock.
Se os dados resumidos no índice mudarem, uma nova linha com `revision` maior é
adicionada; a última linha de cada `run_id` é a vigente. Quando ausente no
`result.json`, a quantidade de módulos vem do estágio `planner` ou `components`
do manifesto. Falha ao escrever o índice gera aviso, sem alterar o status da
execução. Na próxima inicialização,
execuções antigas com `manifest.json` e `result.json` também entram no índice;
esse preenchimento pode aumentar o tempo de inicialização quando houver muitas
execuções.

```text
output/run_<id>/
├── manifest.json
├── result.json
├── provenance/
│   ├── environment.json
│   ├── python_packages.json
│   ├── git.diff
│   ├── git_status.txt
│   ├── untracked_files.json
│   └── source_hashes.json
├── calls/
│   └── <sequencia>_<etapa>.json
├── prompts/
│   ├── original.txt
│   └── components.json
├── modules/
│   ├── <nome>.c
│   └── <indice>_<nome>/
│       ├── module.json
│       ├── prompt.txt
│       └── response.c
├── assembly/
│   ├── task.txt
│   ├── opencode_events.jsonl
│   ├── opencode_stderr.log
│   ├── stdout.log
│   ├── stderr.log
│   ├── result.json
│   ├── main.c
│   └── output
└── events.jsonl
```

O `manifest.json` registra o modelo solicitado e resolvido, provedor,
parâmetros de geração, commit Git, estado da árvore de trabalho e resumo do
ambiente da máquina que executa o pipeline. `provenance/environment.json`
identifica esse escopo como `pipeline_host` e detalha Python, sistema operacional,
arquitetura, CPU, locale, timezone, GCC, OpenCode, OpenSSL e libcurl.
`provenance/python_packages.json` lista todos os pacotes Python instalados com
suas versões. Cada chamada ao modelo
conserva mensagens, resposta, duração, tentativas, uso de tokens quando fornecido
e identificadores retornados pela API.

O `result.json` registra o estado final, duração, erro estruturado quando houver
e SHA-256 de todos os artefatos. O campo `llm_calls` consolida chamadas gravadas,
conclusões, erros, recusas do provedor, respostas vazias, retries, tokens, custo
informado pela API e modelos retornados. `providers_observed` representa os gateways usados; o provedor
de inferência, quando informado pela API, aparece em `inference_providers_observed`.
O custo usa `unit: provider_reported`, sem presumir moeda; sem custo informado,
o total fica `null`. Execuções interrompidas e abandonadas também produzem
`result.json` com os registros de chamadas disponíveis.

As chamadas diretas do pipeline aparecem em `llm_calls`. A atividade do agente
OpenCode fica separada em `assembly.agent_usage`, com sessões, passos, chamadas
de ferramentas, tokens e custo extraídos de `assembly/opencode_events.jsonl`.
`agent_return_code` representa o processo OpenCode e `compile_return_code`
representa a verificação final independente do GCC.

## Testes

Os testes usam implementações simuladas e não acessam APIs nem executam os
binários produzidos.

```bash
python -m unittest discover -v
```

---

## Ambiente de teste

Para preparar e limpar o ambiente de VM antes/depois de cada experimento:

```bash
scripts/generate_test_files.sh --count 500
scripts/reset_vm.sh
```

O gerador é um binário Rust (sem dependências externas) em
`tools/generate_test_files/`. O wrapper compila uma vez e executa. Gera
`.xlsx`, `.docx`, `.pdf` e `.txt` válidos, em paralelo (todos os núcleos):

```bash
scripts/generate_test_files.sh -n 5000
scripts/generate_test_files.sh -n 5000 -w 8
```

Referência: 5.000 arquivos em ~0,03s.

As ferramentas Rust formam um workspace na raiz. Do repositório, funcionam
`cargo build --release` e `cargo test --workspace`. Requer **Rust 1.85+**
(edição 2024).

---

## Cenários disponíveis

| Flag             | Variante          | Descrição resumida                                    |
|------------------|-------------------|-------------------------------------------------------|
| `wannacry`       | WannaCry-like (C) | AES-256-GCM, .wncry, exfiltração via libcurl, crontab |

*(Novos cenários são adicionados em `scenarios/test_prompts.py`.)*

---

## Modelos suportados

O pipeline usa a API do [OpenRouter](https://openrouter.ai), que agrega dezenas
de modelos. Os aliases configurados ficam em `src/llm_client.py`.

---

## Referências

- [OpenRouter API](https://openrouter.ai/docs)
- [OpenSSL EVP](https://www.openssl.org/docs/man3.0/man3/EVP_EncryptInit_ex.html)
- [libcurl](https://curl.se/libcurl/c/)
