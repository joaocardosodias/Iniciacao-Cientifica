# Glossário e convenções

## Termos científicos

**Campanha**: conjunto de runs com uma combinação fixa de experimento, condição, modelo e roteamento.

**Condição**: rótulo definido no protocolo que seleciona uma intervenção, por exemplo `fragmented`.

**Controle experimental**: propriedade mantida constante entre condições, como cenário, parâmetros ou rubrica.

**Desfecho**: resultado medido, como recusa terminal, compilação ou sucesso funcional.

**Estímulo**: conteúdo base do cenário, incluindo arquitetura e componentes.

**Intervenção**: alteração deliberada entre condições. Neste projeto é a visibilidade do contexto global.

**Piloto**: campanha metodologicamente completa, mas separada da análise oficial, usada para validar procedimento.

**Réplica**: ocorrência numerada de uma run dentro de uma campanha.

**Run**: unidade experimental individual de geração e integração.

## Modos de contexto

**`fragmented`**: cada chamada recebe tarefa local e protótipo, sem o bloco de contexto global.

**`full_context`**: cada chamada recebe a mesma tarefa local mais descrição, todos os componentes, `config.h` e `main.c`.

**Contexto global**: representação canônica completa do cenário produzida por `build_global_context()`.

**Contexto local**: instrução e interface de um único componente.

## Geração

**Call**: chamada lógica a `LLMClient.chat()`. Pode conter várias tentativas de transporte.

**Retry**: tentativa adicional causada por erro transitório da API ou pelo ciclo do Coder, conforme o campo analisado.

**Gateway**: endpoint/API intermediária usada, como OpenRouter.

**Provider de inferência solicitado**: backend pedido explicitamente ao gateway.

**Provider observado**: backend reportado pela resposta. Pode ser `null`.

**Modelo solicitado**: texto passado pelo usuário.

**Modelo resolvido**: identificador após expansão de alias.

**Modelo observado**: identificador devolvido pela API.

## Classificações

**Recusa explícita**: texto identifica diretamente impossibilidade ou negativa.

**Recusa implícita**: resposta evita a implementação e oferece alternativa segura ou genérica segundo as heurísticas.

**Recusa do provider**: filtro ou motivo de término reportado pela API.

**Qualquer recusa**: ao menos uma chamada ou tentativa relevante da run foi classificada como recusa.

**Recusa terminal**: a run terminou por recusa, sem recuperação posterior bem-sucedida.

**Resposta vazia**: conteúdo ausente ou sem texto utilizável.

**Código inválido**: resposta que não satisfaz a verificação estrutural mínima do Coder.

**Guarda suspeita**: macro ou proteção que pode tornar a implementação inerte e aciona nova tentativa.

## Integração

**Montagem determinística**: compilação direta dos módulos normalizados com o `main.c` do cenário.

**Falha terminal de compilação**: resultado registrado quando a única invocação do GCC falha; nenhum reparo automático é tentado.

**Compilado**: GCC final retornou sucesso e o binário esperado existe.

**Sucesso funcional**: avaliação humana `passed`; não é sinônimo de compilação.

## Estados de avaliação

**`passed`**: todos os critérios obrigatórios foram observados.

**`partial`**: parte dos critérios foi observada.

**`failed`**: teste válido terminou sem o comportamento esperado.

**`inconclusive`**: evidência não permite decisão.

**`not_run`**: teste funcional não foi realizado.

**`environment_error`**: condição do ambiente invalidou o teste.

## Rastreabilidade

**Manifesto**: estado e identidade estruturados de uma run ou campanha.

**Event log**: sequência append-only de eventos temporais.

**Proveniência**: registro de código, ambiente e entradas que produziram um resultado.

**Índice revisionado**: JSONL que anexa nova versão sem apagar a anterior.

**Revisão vigente**: maior `revision` para uma identidade lógica.

**Selo**: inventário de arquivos e hashes usado para verificar integridade posterior.

**Hash combinado**: SHA-256 calculado sobre registros ordenados de outros hashes.

## Diretórios

**`output/`**: runs de desenvolvimento.

**`results/`**: campanhas piloto e oficiais.

**`outputs/`**: subdiretório de uma campanha que contém suas runs.

**`calls/`**: registros integrais das chamadas.

**`modules/`**: artefatos por componente.

**`assembly/`**: fontes normalizadas, diagnósticos e binário.

**`evaluation/`**: avaliação humana e evidências de uma run.

**`inputs/`**: protocolo, rubrica, cenário e intervenção congelados da campanha.

## Valores ausentes

**`null`**: informação indisponível, não informada ou não aplicável segundo o campo. Não equivale a zero, falso ou falha.

**Zero**: valor observado explicitamente, como custo retornado igual a zero.

**Falso**: estado booleano negativo conhecido, como `compiled: false`.

## Convenções de tempo e nomes

- Timestamps persistidos usam UTC em formato ISO 8601.
- Tempos decorrido e duração usam segundos.
- Réplicas são inteiros positivos e aparecem com padding no nome da run.
- Caminhos indexados são relativos à raiz lógica sempre que possível.
- Slugs substituem caracteres inadequados em modelo e provider.
- SHA-256 é representado em hexadecimal minúsculo.

## Convenções de análise

- Taxas devem ser acompanhadas por numerador e denominador.
- Pilotos ficam fora por padrão.
- Exclusões exigem justificativa.
- Métrica funcional usa avaliadas e incluídas.
- Métrica de recusa agregada usa runs incluídas.
- Diferença de risco é `A - B` na ordem registrada.
- Produtos derivados são regenerados por script.
