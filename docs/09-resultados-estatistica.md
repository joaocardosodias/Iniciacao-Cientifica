# Resultados e análise estatística

## 1. Filosofia da consolidação

Resultados consolidados são derivados das evidências, nunca preenchidos manualmente. O fluxo é:

```text
campaign.json
+ manifest.json e result.json de cada run
+ evaluation/manual.json vigente
+ evaluations.jsonl
        ↓
tools/build_results.py
        ↓
runs.csv + summary.csv + summary.json + exclusions.csv + provenance.json
        ↓
tools/build_aggregate.py
        ↓
all_runs.csv + resumos + comparações + statistics.json
```

Se uma avaliação mudar, regenere a campanha e depois o agregado. Os arquivos derivados devem ser substituídos pelo script, não corrigidos em editor de planilhas.

## 2. Construção por campanha

`build_results()` atualiza a contagem de avaliações, verifica selos existentes das runs, percorre a lista de réplicas e combina os dados. Depois:

1. ordena linhas por réplica;
2. grava `runs.csv` atomicamente;
3. calcula o resumo;
4. grava CSV e JSON;
5. lista exclusões;
6. calcula proveniência de entradas e saídas;
7. emite `results.built`;
8. renova selos das runs;
9. sela a campanha.

Uma run sem diretório, como uma falha de inicialização registrada apenas na campanha, ainda recebe uma linha reduzida. Ela não possui avaliação manual localizável e recebe `functional_status: not_run`, `evaluated: false` e inclusão padrão verdadeira no CSV.

## 3. Colunas de `runs.csv`

| Campo | Significado |
|---|---|
| `replicate` | Número da réplica |
| `run_id` | Identidade da run |
| `context_mode` | Visibilidade efetiva |
| `status` | Estado automático terminal |
| `compiled` | Binário validado pelo GCC |
| `error_type` | Classe da exceção terminal |
| `duration_seconds` | Duração da run |
| `llm_calls` | Chamadas lógicas registradas |
| `llm_refusals` | Chamadas classificadas como recusa |
| `provider_refusal_calls` | Recusas reportadas pelo provider |
| `textual_refusal_calls` | Recusas detectadas no texto |
| `explicit_refusal_calls` | Recusas explícitas |
| `implicit_refusal_calls` | Alternativas seguras ou evasivas classificadas como implícitas |
| `empty_response_calls` | Respostas vazias |
| `invalid_code_calls` | Respostas sem estrutura mínima de código |
| `any_refusal` | Alguma tentativa da run recusou |
| `run_refusal` | Desfecho terminal da run foi recusa |
| `terminal_refusal_type` | Tipo terminal, quando aplicável |
| `llm_errors` | Chamadas com erro |
| `llm_retries` | Tentativas adicionais |
| `tokens_total` | Tokens totais informados |
| `cost_total` | Custo informado |
| `functional_status` | Avaliação funcional vigente |
| `evaluated` | Existência de avaliação manual |
| `evaluator` | Identificador do avaliador |
| `evaluated_at` | Timestamp da avaliação |
| `include_in_analysis` | Inclusão nos denominadores analíticos |
| `exclusion_reason` | Justificativa da exclusão |
| `run_path` | Caminho relativo da run |

## 4. Contagens por campanha

`summary.json` registra:

- `planned`;
- `started`;
- `completed`;
- `failed`;
- `evaluated`;
- `pending_evaluation`;
- `compiled`;
- `functional_passed`;
- `functional_partial`;
- `functional_inconclusive`;
- `environment_errors`;
- `excluded`;
- runs com recusa terminal;
- runs com qualquer recusa;
- runs com recusa do provider;
- runs com recusa textual;
- chamadas recusadas por categoria.

`failed` nessa camada é toda linha cujo status não é `completed`. Consulte `error_type` para separar causas.

## 5. Taxas e denominadores

| Métrica | Numerador | Denominador na campanha |
|---|---|---|
| `generation_completed` | Runs com status `completed` | Runs planejadas |
| `compilation` | Runs com `compiled=true` | Runs iniciadas |
| `functional_success` | Avaliadas, incluídas e `passed` | Avaliadas e incluídas |
| `runs_with_any_refusal` | Runs com qualquer tentativa recusada | Runs iniciadas |
| `run_refusal_rate` | Runs com recusa terminal | Runs iniciadas |
| `provider_refusal` | Runs com ao menos uma recusa do provider | Runs iniciadas |
| `textual_refusal` | Runs com ao menos uma recusa textual | Runs iniciadas |

Há uma diferença importante: no resumo simples da campanha, taxas de recusa usam runs iniciadas; no agregado, métricas comparativas usam runs com `include_in_analysis=true`. Antes de publicar, as exclusões devem estar completas e os denominadores devem ser descritos explicitamente.

## 6. Uso e custo

O resumo calcula:

- custo total e médio entre runs com custo informado;
- tokens totais e médios entre runs com telemetria;
- duração média entre runs com duração disponível;
- média de tentativas como chamadas mais retries.

Quando nenhuma observação numérica existe, o valor é `null`. A média não imputa zeros para dados ausentes. Ao relatar custo, informe quantas runs tinham custo disponível.

## 7. Exclusões

`exclusions.csv` contém somente runs avaliadas com `include_in_analysis=false`. Ele preserva réplica, `run_id`, estado funcional, justificativa e caminho.

Uma run não avaliada não aparece como excluída automaticamente. Ela é pendente. Para análise funcional definitiva, todas as runs elegíveis devem ser avaliadas ou tratadas segundo uma regra registrada.

## 8. Agregação do experimento

`build_aggregate()` encontra `campaign.json` sob `results/*/*/*/`, seleciona o `experiment_id` e remove pilotos por padrão. Para cada campanha:

- gera resultados se faltarem;
- verifica `campaign_seal.json`;
- lê `runs.csv`;
- acrescenta identidade de campanha, modelo, provider, condição e modo.

Os produtos são gravados em:

```text
results/aggregate/<experiment_id>/
├── all_runs.csv
├── summary_by_model.csv
├── summary_by_condition.csv
├── condition_comparisons.csv
├── statistics.json
├── provenance.json
├── figures/
└── tables/
```

`--include-pilots` existe para análises diagnósticas. Não use pilotos na estimativa oficial sem justificativa metodológica prévia.

## 9. Verificação de comparabilidade

Antes de combinar, o agregador exige:

- um único `stimulus_sha256`;
- um único `protocol_sha256`;
- um único `rubric_sha256`;
- um único `full_context_sha256`;
- associação unívoca entre condição e `context_mode`.

Uma divergência gera erro em vez de produzir uma comparação enganosa. `intervention_sha256` pode diferir entre condições por definição.

## 10. Resumo por grupos

`summary_by_model.csv` agrupa por modelo, gateway, provider de inferência e condição. `summary_by_condition.csv` agrega por condição em todas as campanhas selecionadas.

Cada grupo contém:

- runs totais, incluídas e excluídas;
- avaliadas;
- geração concluída;
- compiladas;
- sucessos funcionais;
- taxa funcional e intervalo de 95%;
- recusas terminais e qualquer recusa;
- taxa de recusa e intervalo de 95%;
- custo total e custo por sucesso.

O resumo por condição pode misturar modelos. Use-o apenas como panorama; inferências sobre efeito dentro de um modelo devem usar o agrupamento e as comparações estratificadas.

## 11. Intervalo de Wilson

Para uma proporção com `x` sucessos em `n` observações, o projeto usa intervalo score de Wilson com `z` de aproximadamente 1,96. Ele é preferível ao intervalo normal simples quando `n` é moderado ou a proporção está perto de zero ou um.

O retorno contém contagem, total, proporção e limites inferior e superior de 95%. Quando `n=0`, taxa e limites são `null`.

Intervalo de confiança não é probabilidade de 95% de o parâmetro fixo estar naquele intervalo. Ele descreve o comportamento do procedimento sob repetições hipotéticas.

## 12. Diferença de riscos

Para cada par de condições dentro da mesma combinação de modelo e providers, o projeto calcula:

`diferença = taxa da condição A - taxa da condição B`

São produzidas diferenças para sucesso funcional e recusa terminal. Os limites usam uma construção Newcombe baseada em intervalos de Wilson. Valores positivos indicam taxa maior em A; negativos, taxa menor em A. A interpretação depende da ordem alfabética gravada em `condition_a` e `condition_b`, não de uma suposição sobre qual é tratamento.

Sempre reporte a ordem, as duas contagens e o intervalo. Se o intervalo inclui zero, os dados são compatíveis com ausência de diferença no nível adotado, sem provar equivalência.

## 13. Denominadores no agregado

- Sucesso funcional usa somente runs incluídas e avaliadas.
- Recusa terminal usa todas as runs incluídas, avaliadas ou não.
- Compilação e geração usam runs incluídas no resumo por grupo.
- `runs` inclui também excluídas para transparência.

Essa diferença é intencional porque recusa é derivada da geração, enquanto sucesso funcional requer avaliação. O artigo deve evitar comparar porcentagens sem informar esses universos.

## 14. Integridade antes da análise

O agregador se recusa a usar campanha cujo selo existente seja inválido. Se produtos ainda não existem, ele os constrói e sela. Isso garante que `statistics.json` aponte para campanhas verificadas naquele momento.

Uma nova avaliação altera arquivos fora do selo original da run, mas muda a campanha. Regenere os resultados para atualizar o selo de campanha e a proveniência.

## 15. Interpretação recomendada

Apresente primeiro contagens brutas e fluxograma das runs. Em seguida apresente a métrica primária com intervalo, depois métricas secundárias. Separe:

- recusa do provider;
- recusa textual;
- recusa terminal;
- geração completa;
- compilação;
- comportamento funcional.

Não converta “não recusou” em “gerou artefato funcional”. São etapas distintas da cadeia.

## 16. Análises não implementadas

O código atual não implementa teste de hipótese exato, regressão, ajuste por múltiplas comparações, análise temporal, análise de sobrevivência, pareamento ou tamanho de efeito padronizado além da diferença de riscos.

Se forem adicionados, devem ser pré-especificados, versionados, testados e documentados. Cálculos exploratórios devem ser identificados como exploratórios.

## 17. Proveniência da análise

`provenance.json` da campanha lista cada fonte usada, tamanho e hash, além dos hashes dos produtos. O agregado lista campanhas, controles e hashes combinados dos selos.

Esse encadeamento permite responder de quais versões de `manifest.json`, `result.json` e `manual.json` cada tabela foi derivada.
