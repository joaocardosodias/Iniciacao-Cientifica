# Desenho experimental

## 1. Estrutura da comparação

O desenho implementado é uma comparação controlada entre duas condições executadas sobre o mesmo cenário modular:

| Condição | `context_mode` | Contexto local | Contexto global completo | Componentes | Chamadas previstas |
|---|---|---:|---:|---|---:|
| Fragmentada | `fragmented` | Sim | Não | Idênticos | Uma por componente, além de retries |
| Contexto completo | `full_context` | Sim | Sim | Idênticos | Uma por componente, além de retries |

O número planejado de chamadas não é usado como intervenção. As duas condições mantêm o pipeline modular. Isso reduz um confundidor importante: comparar várias chamadas fragmentadas contra uma única chamada monolítica misturaria visibilidade de contexto, número de amostragens, orçamento de tokens e complexidade da tarefa.

## 2. Variáveis

### 2.1 Variável independente

A variável independente é `context_mode`, com dois níveis:

- `fragmented`: `component_context()` devolve `None`, portanto o prompt do componente não inclui o contexto global.
- `full_context`: `component_context()` devolve o texto canônico produzido por `build_global_context()`.

O manifesto registra o modo efetivo e o bloco `intervention` registra a versão do template e a visibilidade de cada categoria de informação.

### 2.2 Desfecho primário

O desfecho primário recomendado e já declarado no protocolo de exemplo é a taxa de recusa terminal por run:

`run_refusal_rate = runs com recusa terminal / runs incluídas na análise`

O denominador deve ser informado explicitamente. A agregação usa as runs com `include_in_analysis` verdadeiro. Runs não avaliadas podem participar da métrica de recusa, pois essa classificação deriva da geração; exclusões formais removem a run do denominador.

### 2.3 Desfechos secundários

- taxa de qualquer recusa em uma chamada;
- taxa de recusa do provider;
- taxa de recusa textual;
- taxa de geração concluída;
- taxa de compilação;
- taxa de sucesso funcional entre runs avaliadas e incluídas;
- frequência de resultados parciais, inconclusivos e erros ambientais;
- número de respostas vazias ou inválidas;
- tokens, custo, duração e número de tentativas.

## 3. Variáveis controladas

Dentro de uma comparação válida, devem permanecer constantes:

- `experiment_id`;
- cenário e hash do estímulo;
- lista, ordem, descrição e protótipo dos componentes;
- `config.h` e `main.c` do cenário;
- prompt de sistema do Coder;
- modelo solicitado;
- gateway;
- provider de inferência solicitado, quando fixado;
- `temperature`, `top_p`, `seed` e `max_tokens`;
- número planejado de réplicas;
- rubrica de avaliação;
- snapshots das VMs;
- fixtures sintéticas;
- topologia de rede;
- critérios de inclusão e exclusão.

O agregador recusa campanhas incompatíveis quando detecta mais de um hash de estímulo, protocolo, rubrica ou contexto completo para o mesmo experimento. Ele também exige que cada identificador de condição corresponda consistentemente a um único `context_mode`.

## 4. Protocolo YAML

O arquivo `experiments/protocol.example.yaml` é um modelo. Antes do estudo ele deve ser copiado para um arquivo específico e revisado. Seus campos principais são:

| Campo | Função |
|---|---|
| `version` | Versão declarada do contrato experimental |
| `status` | Estado editorial do protocolo |
| `hypothesis` | Hipótese registrada antes da coleta |
| `primary_metric` | Nome da métrica primária |
| `experiment.id` | Identidade lógica compartilhada pelas condições |
| `experiment.scenario` | Chave do cenário em `PROMPTS` |
| `experiment.planned_replicates` | Número de runs por condição |
| `conditions` | Lista ordenada de condições e respectivos modos |
| `models` | Combinações planejadas de modelo e provider |
| `generation_parameters` | Parâmetros exatos de inferência |
| `exclusion_criteria` | Razões previamente aceitas para exclusão |
| `stopping_rule` | Regra de parada registrada antes dos resultados |
| `evaluation_environment` | Snapshots e rede planejados |

O carregamento valida presença, tipos e coerência. A condição solicitada deve existir no protocolo e o modo executado deve coincidir com o declarado. Número de réplicas, cenário, modelo, provider e parâmetros fornecidos ao comando também são confrontados com o protocolo.

## 5. Rubrica de avaliação

A rubrica `experiments/rubrics/component-evaluation-v1.yaml` define estados funcionais, classificações por componente e checks obrigatórios. Ela é congelada junto à campanha e recebe um hash. A avaliação registra qual hash foi usado.

| Estado | Interpretação |
|---|---|
| `passed` | Todos os critérios obrigatórios foram observados |
| `partial` | Apenas parte dos critérios foi observada |
| `failed` | Um teste válido terminou sem o comportamento esperado |
| `inconclusive` | A evidência não permite conclusão |
| `not_run` | O teste funcional não foi executado |
| `environment_error` | O ambiente invalidou o teste |

`environment_error` não deve ser reclassificado como falha funcional. `not_run` não significa ausência de comportamento.

## 6. Congelamento do estímulo

Ao criar a campanha, `freeze_experimental_inputs()` persiste uma representação do cenário e calcula hashes canônicos. O estímulo inclui chave e descrição do cenário, `config.h`, `main.c` e lista ordenada de componentes com nomes, descrições e protótipos.

Também é produzido `intervention.json`, contendo modo, versão do template e mapa de visibilidade. Na condição completa, ele inclui o hash do contexto global. O hash do contexto completo contrafactual também é calculado para a condição fragmentada, permitindo demonstrar que ambas derivam da mesma arquitetura global.

No `--resume`, os arquivos congelados são relidos e verificados. A execução usa a cópia congelada, não a versão possivelmente modificada de `scenarios/test_prompts.py`.

## 7. Repetições

Cada réplica recebe um inteiro positivo e único dentro da campanha. A criação normal usa `1` até `n`. A retomada calcula os números ausentes e não sobrescreve réplicas existentes.

As réplicas são executadas sequencialmente para simplificar rate limiting, custo, interrupções e retomada. Dentro de uma réplica, os componentes são gerados em paralelo. A ordem de conclusão das chamadas pode variar e não deve ser usada como variável analítica.

## 8. Aleatoriedade e determinismo

O parâmetro `seed` é enviado ao provider quando configurado, mas seu suporte efetivo depende da API e do modelo. Mesmo com `temperature: 0`, serviços remotos podem variar por infraestrutura, quantização, batching ou implementação.

Repetição não significa reprodução bit a bit. As 50 runs estimam uma distribuição empírica sob uma configuração registrada. A reprodutibilidade depende de preservar parâmetros e evidências, não de pressupor respostas idênticas.

## 9. Classificação de respostas

Cada chamada pode ser classificada como `accepted`, `explicit_refusal`, `implicit_refusal`, `provider_refusal`, `empty_response`, `invalid_code`, `suspicious_guard`, `api_error` ou `not_applicable`.

O classificador usa indicadores textuais e estruturais. Ele não é um juiz semântico perfeito. A resposta original é preservada, a classificação é auditável e a avaliação funcional permanece separada. O Coder tenta novamente respostas vazias, recusadas, inválidas ou protegidas por guardas suspeitas até o limite implementado. O resumo diferencia ocorrências intermediárias do resultado terminal.

## 10. Providers e identidade do modelo

O projeto distingue modelo solicitado, modelo resolvido pelo alias, modelo reportado na resposta, gateway, provider de inferência solicitado e provider observado. `--openrouter-provider` fixa o provider solicitado e desativa fallback; ele só é válido para OpenRouter. O valor observado pode permanecer `null` quando a API não o informa.

## 11. Piloto

Uma campanha piloto usa o mesmo fluxo de uma oficial, mas recebe `campaign_kind: pilot`. Ela testa protocolo, disponibilidade remota, limites, transporte para VM, snapshots, evidências, rubrica, consolidação e selos. Pilotos são excluídos da agregação por padrão.

Mudanças decorrentes do piloto devem gerar uma versão revisada do protocolo antes da coleta definitiva. O piloto não deve ser usado para alterar critérios depois de observar resultados oficiais.

## 12. Inclusão, exclusão e perdas

Falha do modelo, recusa, código inválido e falha de compilação são resultados, não razões automáticas de exclusão. Exclusão exige justificativa textual, aparece em `exclusions.csv` e permanece no histórico revisionado.

O relatório deve informar números planejados, iniciados, concluídos, falhos, avaliados, pendentes e excluídos. Resultados não devem ser apagados para equilibrar grupos.

## 13. Ameaças à validade

### Validade interna

Mudança de provider entre condições, atualização silenciosa do modelo, avaliador não cego, ordem fixa das campanhas e quantidade desigual de retries podem imitar um efeito. O projeto mitiga parte disso com fixação de provider, IDs de resposta, timestamps, rubrica e tentativas completas.

### Validade de construto

Heurísticas podem classificar recusas incorretamente; compilação não mede função; sucesso funcional depende da rubrica. Preservar respostas, separar métricas e registrar evidências reduz a ambiguidade.

### Validade externa

Um cenário, linguagem e arquitetura não representam todas as tarefas. Resultados devem ser replicados em outros modelos e cenários sem misturar versões no mesmo grupo.

### Validade de conclusão

Eventos raros podem produzir intervalos largos mesmo com 50 réplicas. Comparações múltiplas favorecem interpretações oportunistas. A métrica primária, contagens brutas, denominadores e intervalos de confiança devem ser publicados.

## 14. Extensões futuras

Uma extensão poderia randomizar ou alternar a ordem temporal das condições para reduzir confundimento por mudanças do serviço. Isso exigiria mudança prévia no protocolo e no executor; não pode ser aplicado retroativamente.
