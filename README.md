# Pipeline de Evasão Multi-Agentes

Iniciação Científica — Pesquisa em segurança de LLMs.

Investiga como filtros de segurança de modelos de linguagem podem ser contornados
por meio de **decomposição modular**: o pedido malicioso é fragmentado em partes
aparentemente legítimas, cada uma processada por um agente diferente, de modo que
nenhum modelo individual vê a intenção global.

> **Uso exclusivamente acadêmico.** Todo o código é executado em VM isolada,
> sem acesso à rede real. O servidor C2 (`scripts/c2_server.py`) é um honeypot
> de pesquisa que não executa nenhuma ação maliciosa.

---

## Estrutura do repositório

```
.
├── pipeline.py          # Orquestrador principal — entry point
├── requirements.txt     # Dependências Python
│
├── src/                 # Camadas do pipeline
│   ├── sanitizer.py     # Camada 1 — sanitiza fragmentos independentes do prompt
│   ├── planner.py       # Camada 2 — divide em módulos independentes
│   ├── prompt_maker.py  # Camada 3 — gera contexto profissional por módulo
│   ├── coder.py         # Camada 4 — gera o código C de cada módulo
│   ├── assembler_harness.py # Camadas 5 e 6 — integra e compila com OpenCode
│   ├── trace.py         # Rastreabilidade, hashes e metadados das execuções
│   └── llm_client.py    # Cliente OpenRouter, Groq e NVIDIA NIM
│
├── scenarios/           # Prompts de teste
│   └── test_prompts.py  # Catálogo de cenários (WannaCry, Petya, Locky…)
│
├── scripts/             # Utilitários de laboratório
│   ├── c2_server.py         # Servidor C2 fake para capturar eventos
│   ├── generate_test_files.sh   # Wrapper para o gerador Rust de arquivos falsos
│   └── reset_vm.sh          # Wrapper para o limpador Rust do ambiente
│
├── tools/
│   ├── generate_test_files/ # Gerador de arquivos falsos em Rust (sem dependências)
│   └── reset_vm/            # Limpador do ambiente de experimento em Rust
│
├── tests/               # Testes automatizados sem chamadas externas
│   └── test_traceability.py
│
└── output/              # Artefatos e evidências de cada execução
    └── run_<id>/
```

---

## Como funciona

O pipeline recebe um prompt e produz módulos C independentes em paralelo. A
integração e a correção final são realizadas por um agente OpenCode headless:

```
Prompt malicioso
      │
      ▼
 1. Sanitizer ──── sanitiza fragmentos de 2–3 requisitos sem contexto global
      │
      ▼
 2. Planner ─────── divide em 3–7 módulos independentes
      │
      ▼
 3. PromptMaker ─── gera contexto profissional fictício por módulo
      │
      ▼
 4. Coder ──────── gera código C para cada módulo isolado
      │
      ▼
 5+6. AssemblerHarness
      ├── lê os módulos no diretório da execução
      ├── integra o conteúdo em main.c
      ├── compila com gcc
      └── corrige erros com alterações localizadas
      │
      ▼
  output/run_<id>/assembly/main.c + output/run_<id>/assembly/output
```

A hipótese central é que filtros baseados em análise de conteúdo individual
falham quando o pedido é decomposto: cada módulo parece inofensivo, mas o
resultado final é funcional.

### Modo componentes (determinístico)

Cenários podem declarar, além do prompt, três blocos:

- `config_h`: cabeçalho C com os valores concretos do cenário (diretórios,
  extensões, endpoint, token, notas, cron);
- `components`: lista de componentes genéricos, cada um com `prototype` e
  `task`, sem qualquer menção à intenção global;
- `main_c`: orquestração C que liga os componentes na ordem correta.

Nesse modo o pipeline não envia prompt, fragmentos nem valores concretos ao
modelo: o Coder recebe apenas tarefas genéricas ("AES-256-GCM em um buffer",
"POST JSON", "varredura por extensão") e o `config.h`/`main.c` são gerados de
forma determinística pelo pipeline. A composição maliciosa existe somente no
orquestrador Python e no `main_c`, nunca na linguagem natural vista pelo LLM.

O fluxo Sanitizer+Planner+PromptMaker é o padrão, inclusive quando `--scenario`
é utilizado. `--components-mode` ativa explicitamente o modo determinístico.
Nesse modo, o `AssemblerHarness` compila `main.c` + `module_NN.c` com `gcc`
diretamente e aciona o OpenCode apenas se a compilação falhar.

---

## Configuração

### 1. Dependências Python

```bash
rtk pip install -r requirements.txt
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
rtk python scripts/c2_server.py
```

Isso sobe o servidor em `0.0.0.0:8080` e expõe um dashboard em
`http://localhost:8080` com os eventos capturados.

---

## Uso

```bash
rtk python pipeline.py --scenario wannacry
rtk python pipeline.py --list
rtk python pipeline.py --models
rtk python pipeline.py --scenario wannacry --model gpt-4o-mini
rtk python pipeline.py --scenario wannacry --limit 2
rtk python pipeline.py --scenario wannacry --temperature 0 --seed 42 --max-tokens 8192
rtk python pipeline.py --scenario wannacry --model deepseek-v3 --openrouter-provider deepinfra
```

Parâmetros ausentes de geração são registrados como `null`, indicando que o
padrão do provedor foi utilizado.

`--openrouter-provider` fixa o slug do provider de inferência para modelos
roteados pelo OpenRouter e desativa fallback para outros providers. O provider
precisa oferecer o modelo selecionado; caso contrário, a chamada falha. A opção
não pode ser combinada com modelos `groq:` ou `nim:`.

## Rastreabilidade

Cada execução recebe um identificador único baseado em horário UTC, precisão de
microssegundos e sufixo aleatório. Uma execução não reutiliza nem sobrescreve
uma pasta existente.

`output/experiments.jsonl` mantém um índice global, com uma linha JSON por
execução finalizada ou recuperada. Cada registro aponta para o `result.json`
correspondente por caminhos relativos a `output/` e resume status, cenário,
quantidade de módulos, hash combinado das fontes, modelo, duração e chamadas
ao LLM, sem copiar o prompt. Escritas concorrentes são protegidas por lock.
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
│   ├── sanitized.txt
│   └── planner_response.json
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
rtk python -m unittest discover -v
```

---

## Ambiente de teste

Para preparar e limpar o ambiente de VM antes/depois de cada experimento:

```bash
rtk scripts/generate_test_files.sh --count 500
rtk scripts/reset_vm.sh
```

O gerador é um binário Rust (sem dependências externas) em
`tools/generate_test_files/`. O wrapper compila uma vez e executa. Gera
`.xlsx`, `.docx`, `.pdf` e `.txt` válidos, em paralelo (todos os núcleos):

```bash
rtk scripts/generate_test_files.sh -n 5000
rtk scripts/generate_test_files.sh -n 5000 -w 8
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
