# Operação de campanhas

## 1. Preparação do ambiente

Crie um ambiente Python isolado e instale as versões travadas:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
```

Configure a credencial do gateway em `.env` ou no ambiente. O nome esperado depende do gateway resolvido pelo modelo. O valor não será incorporado aos artefatos, mas o preflight registrará se a variável estava disponível.

Confirme ferramentas e cenários:

```bash
python pipeline.py --models
python pipeline.py --list
python -m unittest discover -s tests -v
```

## 2. Execução de desenvolvimento

Uma execução normal grava em `output/`:

```bash
python pipeline.py \
  --scenario wannacry \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16 \
  --context-mode fragmented \
  --temperature 0 \
  --seed 42 \
  --max-tokens 8192
```

Para exercitar a condição completa no modo de desenvolvimento:

```bash
python pipeline.py \
  --scenario wannacry \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16 \
  --context-mode full_context \
  --temperature 0 \
  --seed 42 \
  --max-tokens 8192
```

Essas runs têm `run_purpose: development` e não entram automaticamente em análises oficiais.

## 3. Preparação do protocolo oficial

Copie o exemplo para um arquivo específico do estudo e altere `status` para `frozen` somente depois da revisão:

```bash
cp experiments/protocol.example.yaml experiments/protocol.estudo-01.yaml
```

O protocolo deve coincidir exatamente com o comando:

- `experiment.id` igual a `--experiment-id`;
- cenário igual a `--scenario`;
- réplicas iguais a `--runs`;
- modelo igual ao solicitado ou ao resolvido;
- provider igual ao provider de inferência fixado ou gateway;
- parâmetros iguais, inclusive valores `null`;
- condições mapeadas aos modos corretos.

Uma campanha nova rejeita protocolo com `status` diferente de `frozen`.

## 4. Campanha piloto

Antes das 50 runs, execute um piloto pequeno com protocolo próprio, por exemplo três réplicas por condição. O número do arquivo precisa ser três, porque o validador confronta protocolo e CLI.

```bash
python pipeline.py \
  --official \
  --pilot \
  --all-conditions \
  --experiment-id estudo-01-piloto \
  --scenario wannacry \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16 \
  --runs 3 \
  --protocol experiments/protocol.estudo-01-piloto.yaml \
  --rubric experiments/rubrics/component-evaluation-v1.yaml \
  --temperature 0 \
  --seed 42 \
  --max-tokens 8192
```

O piloto é armazenado em `results/`, recebe toda a rastreabilidade, mas é excluído dos agregados por padrão.

## 5. Campanha oficial com as duas condições

O comando recomendado para o estudo comparativo é:

```bash
python pipeline.py \
  --official \
  --all-conditions \
  --experiment-id estudo-01 \
  --scenario wannacry \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16 \
  --runs 50 \
  --protocol experiments/protocol.estudo-01.yaml \
  --rubric experiments/rubrics/component-evaluation-v1.yaml \
  --temperature 0 \
  --seed 42 \
  --max-tokens 8192
```

`--all-conditions` lê a lista de condições do protocolo e cria uma campanha separada para cada uma. O valor `--runs 50` aplica-se a cada condição. Com duas condições, o total planejado é 100 runs.

As condições são executadas na ordem do protocolo. Runs são sequenciais; componentes dentro de uma run continuam paralelos.

## 6. Campanha de uma condição

Também é possível executar separadamente:

```bash
python pipeline.py \
  --official \
  --experiment-id estudo-01 \
  --condition fragmented \
  --scenario wannacry \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16 \
  --runs 50 \
  --protocol experiments/protocol.estudo-01.yaml \
  --rubric experiments/rubrics/component-evaluation-v1.yaml \
  --temperature 0 \
  --seed 42 \
  --max-tokens 8192
```

O `context_mode` vem do protocolo. Passar `--context-mode` é opcional em campanha oficial e, se passado, precisa coincidir com a condição.

## 7. Criação e prevenção de duplicatas

Antes de executar as condições, o modo `--all-conditions` verifica se os diretórios alvo já existem. Se existir uma campanha e `--resume` não estiver presente, o comando aborta. Uma campanha nunca é substituída silenciosamente.

Falhas individuais durante a geração não abortam automaticamente o lote. A run falha é registrada, adicionada à campanha e a próxima réplica é iniciada. Interrupções explícitas de processo marcam a campanha como interrompida.

## 8. Retomada

Para retomar todas as condições existentes:

```bash
python pipeline.py \
  --official \
  --resume \
  --all-conditions \
  --experiment-id estudo-01 \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16
```

Para uma condição:

```bash
python pipeline.py \
  --official \
  --resume \
  --experiment-id estudo-01 \
  --condition fragmented \
  --model openai/gpt-oss-120b \
  --openrouter-provider cerebras/fp16
```

Na retomada:

- `--runs` não é aceito;
- cenário e total vêm da campanha;
- parâmetros vêm da campanha;
- entradas vêm da cópia congelada;
- réplicas existentes são preservadas;
- somente números ausentes são executados;
- o preflight roda novamente.

Modelo e provider na busca precisam identificar inequivocamente a campanha.

## 9. Atraso entre chamadas

`--limit` ou `-L` define segundos de espera usados pelo cliente para modular a cadência. O valor entra em `generation_parameters` e deve coincidir com o protocolo quando fizer parte de campanha oficial.

O retry de erros transitórios possui backoff próprio. O atraso configurado e o backoff não são a mesma coisa.

## 10. Provider OpenRouter

`--openrouter-provider` solicita um provider de inferência específico e desativa fallback no roteamento. Isso é útil para controlar desempenho e identidade experimental. O valor deve usar a forma aceita pelo gateway e constar no protocolo.

O campo solicitado não prova o provider observado. Confira `calls/*.json` e os resumos. Se a API não retornar o observado, ele permanecerá `null`.

## 11. Monitoramento durante a geração

Durante uma campanha, acompanhe sem editar:

- `campaign.json` para contagens e status;
- `events.jsonl` na raiz da campanha para eventos da campanha;
- `outputs/` para runs criadas;
- `events.jsonl` da run ativa;
- `calls/` para término das chamadas;
- espaço livre em disco;
- limites e saldo do provider.

Não corrija manualmente fontes de uma run oficial. Qualquer edição muda a evidência e pode invalidar o selo.

Não execute dois processos com `--resume` sobre a mesma campanha. Os índices JSONL usam lock de arquivo, mas as atualizações de `campaign.json` não constituem coordenação multiprocesso. A execução oficial foi desenhada para um único orquestrador por campanha. Campanhas distintas também devem permanecer sequenciais quando a ordem faz parte do protocolo.

## 12. Após a geração

Quando todas as réplicas terminam, a campanha recebe `generation_completed`, mesmo que algumas runs tenham falhado. As contagens separam concluídas e falhas.

Faça uma verificação inicial:

```bash
python tools/build_results.py \
  --experiment-id estudo-01 \
  --all-conditions \
  --model openai/gpt-oss-120b \
  --provider cerebras/fp16
```

Antes das avaliações, é esperado que existam runs pendentes e estados funcionais `not_run`.

## 13. Listagem de pendências

```bash
python tools/record_evaluation.py \
  --experiment-id estudo-01 \
  --all-conditions \
  --model openai/gpt-oss-120b \
  --provider cerebras/fp16 \
  --list-pending
```

O comando lista condição, réplica, `run_id` e status de geração para registros que possuem diretório de run. Uma falha de inicialização sem `run_id` nem caminho permanece no manifesto e no CSV, mas não aparece como run avaliável nessa listagem. A ordem em que as avaliações são registradas não altera o resultado consolidado.

## 14. Fluxo com Git e VMs

Como `output/` e `results/` podem ser rastreados para transporte no ambiente atual, um fluxo possível é:

1. execute as campanhas de um modelo;
2. confira quantidade e integridade local;
3. faça commit dos artefatos que sua política permite transportar;
4. clone ou atualize o repositório nas VMs;
5. teste uma run por vez;
6. copie evidências para a estrutura de avaliação;
7. registre avaliações com a ferramenta;
8. faça novo commit dos registros e evidências;
9. consolide o modelo;
10. repita com o modelo seguinte.

Antes de versionar, verifique se chamadas e artefatos podem ser armazenados naquele remoto. Nunca inclua `.env`, credenciais ou dados reais.

## 15. Campanhas de modelos adicionais

Cada novo modelo/provider recebe diretório próprio. O `experiment_id` pode permanecer igual se o protocolo declara todos os modelos e os demais controles são comparáveis. Não reutilize um diretório de campanha; a identidade do modelo faz parte do caminho.

Se parâmetros, cenário, rubrica ou protocolo metodológico mudarem, use nova versão de experimento. O agregador deve recusar controles divergentes em uma mesma comparação.

## 16. Finalização da análise

Depois de todas as avaliações:

```bash
python tools/build_results.py \
  --experiment-id estudo-01 \
  --all-conditions \
  --model openai/gpt-oss-120b \
  --provider cerebras/fp16

python tools/build_aggregate.py \
  --experiment-id estudo-01
```

Verifique os selos após a consolidação:

```bash
python tools/verify_campaign.py results/<modelo>/<experimento>/<condicao>
python tools/verify_run.py results/<modelo>/<experimento>/<condicao>/outputs/<run>
```

Uma alteração posterior de avaliação exige nova consolidação e novo selo de campanha.

## 17. Erros operacionais comuns

- Protocolo ainda com `status: draft`.
- `--runs` diferente de `planned_replicates`.
- Alias de modelo que não corresponde ao protocolo.
- Provider do protocolo diferente do provider fixado.
- Parâmetro omitido na CLI, mas explícito no protocolo.
- Uso simultâneo de `--condition` e `--all-conditions`.
- Uso de `--resume` com `--runs`.
- Tentativa de usar `--openrouter-provider` em outro gateway.
- Avaliação sem restaurar o snapshot.
- Confundir 50 por condição com 50 no total.
- Editar CSV em vez de corrigir a avaliação de origem e regenerar.
