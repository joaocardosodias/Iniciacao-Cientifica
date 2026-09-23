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
│   ├── sanitizer.py     # Camada 1 — reescreve o prompt com linguagem neutra
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
│   ├── generate_test_files.py  # Cria ambiente de arquivos falsos na VM
│   └── reset_vm.py          # Limpa todos os artefatos do experimento
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
 1. Sanitizer ──── reescreve com linguagem corporativa neutra
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
  output/run_<id>/main.c + output/run_<id>/output
```

A hipótese central é que filtros baseados em análise de conteúdo individual
falham quando o pedido é decomposto: cada módulo parece inofensivo, mas o
resultado final é funcional.

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
```

Parâmetros ausentes de geração são registrados como `null`, indicando que o
padrão do provedor foi utilizado.

## Rastreabilidade

Cada execução recebe um identificador único baseado em horário UTC, precisão de
microssegundos e sufixo aleatório. Uma execução não reutiliza nem sobrescreve
uma pasta existente.

```text
output/run_<id>/
├── manifest.json
├── result.json
├── calls/
│   └── <sequencia>_<etapa>.json
├── prompts/
│   ├── original.txt
│   ├── sanitized.txt
│   └── planner_response.json
├── modules/
│   └── <indice>_<nome>/
│       ├── module.json
│       ├── prompt.txt
│       └── response.c
├── assembly/
│   ├── task.txt
│   ├── stdout.log
│   ├── stderr.log
│   └── result.json
├── <nome_do_modulo>.c
├── main.c
└── output
```

O `manifest.json` registra o modelo solicitado e resolvido, provedor,
parâmetros de geração, commit Git, estado da árvore de trabalho, versões do
Python, dependências, GCC e OpenCode. Cada chamada ao modelo conserva mensagens,
resposta, duração, tentativas, uso de tokens quando fornecido e identificadores
retornados pela API.

O `result.json` registra o estado final, duração, erro estruturado quando houver
e SHA-256 de todos os artefatos. Execuções interrompidas também produzem esse
arquivo com estado `failed`.

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
rtk python scripts/generate_test_files.py --count 500
rtk python scripts/reset_vm.py
```

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
