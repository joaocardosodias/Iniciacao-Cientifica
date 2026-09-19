# Pipeline de Evasão Multi-Agentes

Iniciação Científica — Pesquisa em segurança de LLMs.

Investiga como filtros de segurança de modelos de linguagem podem ser contornados
por meio de **decomposição modular**: o pedido malicioso é fragmentado em partes
aparentemente legítimas, cada uma processada por um agente diferente, de modo que
nenhum modelo individual vê a intenção global.

> ⚠️ **Uso exclusivamente acadêmico.** Todo o código é executado em VM isolada,
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
│   ├── assembler.py     # Camada 5 — une os módulos em um main.c final
│   ├── fixer.py         # Camada 6 — corrige erros de compilação (gcc + LLM)
│   └── llm_client.py    # Cliente OpenRouter (suporta múltiplos modelos)
│
├── scenarios/           # Prompts de teste
│   └── test_prompts.py  # Catálogo de cenários (WannaCry, Petya, Locky…)
│
├── scripts/             # Utilitários de laboratório
│   ├── c2_server.py         # Servidor C2 fake para capturar eventos
│   ├── generate_test_files.py  # Cria ambiente de arquivos falsos na VM
│   └── reset_vm.py          # Limpa todos os artefatos do experimento
│
└── output/              # Artefatos gerados (ignorados pelo git)
    ├── result_<ts>.c        # Código C gerado
    ├── result_<ts>          # Binário compilado
    └── Makefile_<ts>        # Makefile correspondente
```

---

## Como funciona

O pipeline recebe um prompt descrevendo um comportamento malicioso e o processa
em 6 camadas sequenciais:

```
Prompt malicioso
      │
      ▼
 1. Sanitizer ──── reescreve com linguagem corporativa neutra
      │
      ▼
 2. Planner ─────── divide em 3–6 módulos independentes
      │
      ▼
 3. PromptMaker ─── gera contexto profissional fictício por módulo
      │
      ▼
 4. Coder ──────── gera código C para cada módulo isolado
      │
      ▼
 5. Assembler ───── une todos os módulos em um main.c compilável
      │
      ▼
 6. Fixer ──────── corrige erros de compilação em loop (gcc + LLM)
      │
      ▼
  output/result_<ts>.c  +  binário compilado
```

A hipótese central é que filtros baseados em análise de conteúdo individual
falham quando o pedido é decomposto: cada módulo parece inofensivo, mas o
resultado final é funcional.

---

## Configuração

### 1. Dependências Python

```bash
pip install -r requirements.txt
```

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
# Usando um cenário pré-definido
python pipeline.py --scenario wannacry

# Listando os cenários disponíveis
python pipeline.py --list

# Listando os modelos disponíveis
python pipeline.py --models

# Especificando um modelo
python pipeline.py --scenario wannacry --model gpt-4o-mini

# Sem a camada de correção (Fixer)
python pipeline.py --scenario wannacry --no-fixer

# Limitando as tentativas do Fixer
python pipeline.py --scenario wannacry --fix-attempts 3

# Adicionando delay entre chamadas (evita rate limit)
python pipeline.py --scenario wannacry --limit 2
```

---

## Ambiente de teste

Para preparar e limpar o ambiente de VM antes/depois de cada experimento:

```bash
# Gera arquivos falsos em ~/Documentos_Teste
python scripts/generate_test_files.py --count 500

# Reseta a VM (remove arquivos de teste, criptografados, notas, crontab, logs)
python scripts/reset_vm.py
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
