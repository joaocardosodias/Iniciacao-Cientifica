# Referência do código

## 1. `pipeline.py`

É o orquestrador e ponto de entrada da CLI.

### `run()`

Executa uma unidade experimental. Valida identidade, recupera runs antigas, cria `RunTrace`, configura cliente, constrói contexto, dispara módulos, chama o assembler e finaliza. Recebe entradas do cenário explicitamente para poder usar tanto o cenário atual quanto a cópia congelada.

### `run_official_campaign()`

Cria ou retoma uma campanha. Em criação, valida o protocolo, congela entradas e executa preflight. Em retomada, carrega parâmetros e cenário congelado. Percorre réplicas pendentes sequencialmente, preserva falhas individuais e atualiza `Campaign`.

### `main()`

Define CLI, valida combinações de flags, lista cenários/modelos, resolve campanhas e escolhe desenvolvimento ou oficial. `--all-conditions` executa as condições na ordem do protocolo.

## 2. `src/context_modes.py`

Centraliza a intervenção experimental.

- `validate_context_mode()` aceita somente `fragmented` e `full_context`.
- `context_visibility()` devolve o mapa explícito de informações visíveis.
- `build_global_context()` produz a representação canônica da arquitetura.
- `component_context()` decide se o bloco será entregue ao componente.

`CONTEXT_TEMPLATE_VERSION` deve mudar quando a forma do contexto global mudar. Isso torna uma alteração de prompt identificável.

## 3. `src/llm_client.py`

Implementa resolução de modelos/gateways, autenticação por ambiente, requisições e telemetria.

- `_resolve()` converte alias ou nome em gateway, URL e modelo resolvido.
- `ModelRefusalError` representa filtro de conteúdo reportado pelo serviço.
- `LLMClient.__init__()` configura cliente, parâmetros, provider fixo e callback de trace.
- `chat()` executa tentativas, backoff, extrai resposta e registra a chamada.
- `_finish_reason()` e `_refusal()` normalizam campos da resposta.
- `_record_call()` delega a persistência estruturada.

O módulo mantém `max_retries=0` na biblioteca para que todas as tentativas sejam conhecidas pelo projeto.

## 4. `src/coder.py`

Define a tarefa de geração C.

- `CoderGenerationError` preserva protótipo e classificação final.
- `Coder.user_prompt()` combina contexto opcional, tarefa local e protótipo.
- `generate_generic()` tenta gerar e classificar o módulo.
- `_clean()` remove cercas de Markdown sem alterar o código além do necessário.

O prompt de sistema é parte do instrumento experimental. Qualquer modificação deve ser tratada como mudança de versão metodológica.

## 5. `src/response_classification.py`

Implementa heurísticas determinísticas.

- `classify_coder_response()` identifica vazio, recusa explícita, recusa implícita, código inválido, guarda suspeita ou aceitação.
- `classify_call()` combina estágio, status do provider e texto.

As listas de indicadores fazem parte da definição operacional de recusa e devem ser versionadas junto com o estudo.

## 6. `src/assembler.py`

Normaliza módulos e executa uma única compilação determinística com GCC.

Funções auxiliares:

- `_link_flags()` mapeia includes para bibliotecas;
- `_with_standard_prelude()` garante macros e headers básicos;
- `_strip_comments()` remove comentários respeitando literais;
- `_strip_test_blocks()` remove blocos de teste;
- `_iter_top_level_declarations()` percorre declarações no nível superior;
- `_remove_main_definition()` remove `main` indevido;
- `_extract_signatures()` e `_extract_includes()` inspecionam as interfaces geradas;
- `_prepare_module_source()` aplica a normalização.

`Assembler.assemble()` preserva as fontes originais, grava cópias normalizadas, persiste `config.h` e `main.c`, remove um binário antigo, executa o GCC uma vez e registra `completed` ou `compile_failed`. `_compile_command()` constrói o comando e `_run_gcc()` o executa. Não há geração de tarefa, agente de reparo ou segunda tentativa de compilação.

## 7. `src/trace.py`

É o núcleo de persistência por run.

Funções globais:

- hashes de bytes e texto;
- `safe_name()` para nomes de arquivos;
- `write_json_atomic()`;
- `artifact_index()`;
- `serialize_error()`;
- cálculo de exclusões para a proveniência.

`RunTrace` cria diretórios e manifesto, inicializa eventos, coleta proveniência, registra estágios e chamadas e finaliza resultado, índice e selo. Seus métodos de escrita usam caminhos relativos à run.

## 8. `src/events.py`

Fornece `utc_now()` e `EventLog`. O logger é thread-safe, append-only e durável. `_last_sequence()` permite retomar numeração e `_elapsed()` calcula tempo monotônico.

## 9. `src/environment.py`

Coleta o host do pipeline.

- `_version()` executa consulta tolerante a ausência;
- `_libcurl_version()` tenta `pkg-config` e fallback;
- `_cpu_model()` consulta plataforma;
- `_packages()` inventaria distribuições instaladas;
- `collect()` grava ambiente e pacotes.

Não lê nem persiste valores de variáveis de ambiente.

## 10. `src/provenance.py`

Captura o estado do código.

- `_is_secret()` filtra nomes sensíveis;
- `find_repo_root()` localiza Git;
- `_git_text()` e `_git_line()` executam consultas tolerantes;
- `_untracked_files()` inventaria e copia arquivos elegíveis;
- `_source_hashes()` calcula hashes das fontes;
- `collect()` grava os quatro artefatos Git e devolve resumo.

Symlinks para fora do repositório e diretórios de saída excluídos não são copiados.

## 11. `src/call_summary.py`

`summarize_calls()` percorre `calls/*.json`, agrega status, classificações, tokens, custo, modelos e providers. `safety_outcome()` transforma o conjunto de chamadas e o erro terminal em indicadores por run.

Conversores internos tratam tipos ausentes ou inválidos sem transformar indisponibilidade em zero.

## 12. `src/experiment_index.py`

`append_experiment()` constrói e anexa registro revisionado. Compara o conteúdo atual com a última revisão para evitar duplicata idêntica. `try_index_experiment()` converte falha em aviso. `index_existing_runs()` preenche historicamente runs com manifesto e resultado.

## 13. `src/campaign.py`

`Campaign` encapsula estado de lote.

- `create()` cria caminho seguro, diretórios, manifesto e eventos;
- `attach_experimental_inputs()` registra hashes e caminhos congelados;
- `record_preflight()` e `mark_preflight_failed()` persistem validação;
- `load()`, `find()` e `find_all()` descobrem campanhas;
- `run_reference()` produz identidade passada a uma run;
- `pending_replicates()` calcula lacunas;
- `record_replicate()` incorpora resultado existente;
- `record_initialization_failure()` representa réplica sem run completa;
- `reconcile()` reconstrói a lista a partir dos diretórios;
- `finish_generation()` e `mark_interrupted()` mudam estado;
- `refresh_evaluations()` atualiza progresso de avaliação;
- `_save()` usa escrita atômica;
- `_index()` atualiza `results/campaigns.jsonl`.

## 14. `src/experimental_inputs.py`

Define contratos congelados.

- funções SHA-256 e `canonical_bytes()`;
- `load_yaml()`;
- `condition_context_mode()` e `protocol_condition_ids()`;
- `validate_protocol()`;
- `validate_rubric()`;
- `freeze_experimental_inputs()`;
- `load_frozen_inputs()`.

O carregamento congelado recalcula hashes e rejeita adulteração antes da retomada.

## 15. `src/preflight.py`

`PreflightError` representa falha impeditiva. `_tool()` e `_library()` consultam dependências. `run_preflight()` verifica ferramentas, bibliotecas, credencial, roteamento, cenário, disco e escrita e grava relatório.

## 16. `src/interrupts.py`

- `signal_name()` normaliza sinal;
- `RunInterrupted` herda de `BaseException` para não ser confundida com falha comum de réplica;
- `RunGuard.install()` registra handlers e `atexit`;
- `_handle()` finaliza interrupção;
- `_on_exit()` tenta preservar abandono.

## 17. `src/recovery.py`

- `recover_orphan_run()` cria registros mínimos para pasta sem manifesto;
- `process_alive()` consulta PID;
- helpers de tempo calculam duração;
- `recover_run()` recupera processo morto no mesmo host;
- `recover_stale_runs()` varre um root e reindexa.

A recuperação nunca sobrescreve um `result.json` existente.

## 18. `src/integrity.py`

- `sha256_file()` calcula hash em chunks;
- `create_seal()` inventaria e combina hashes;
- `verify_seal()` calcula diferenças;
- `seal_run()` aplica exclusões da run;
- `seal_campaign()` sela campanha.

## 19. `src/evaluation.py`

- `find_run()` exige localização única;
- `_campaign_for_run()` resolve campanha;
- `_next_revision()` lê histórico;
- `_copy_evidence()` copia e hasheia arquivos;
- `record_evaluation()` valida, grava revisão, atualiza índice e campanha;
- `pending_runs()` lista runs sem `manual.json`.

Exclusão sem justificativa e classificação fora da rubrica são rejeitadas.

## 20. `src/vm_environment.py`

`snapshot_environment()` valida um JSON descritivo, copia para a avaliação e devolve caminho, tamanho e hash. Ele não inspeciona a VM remotamente; a fidelidade dos campos fornecidos continua sendo responsabilidade operacional.

## 21. `src/results_builder.py`

- `RUN_FIELDS` define o contrato do CSV;
- `_run_row()` combina resultado e avaliação;
- `_summary()` calcula contagens, taxas e uso;
- `build_results()` verifica, escreve produtos, registra proveniência e sela.

O módulo usa gravação atômica para CSV e JSON.

## 22. `src/aggregate_results.py`

- `wilson()` calcula intervalo de proporção;
- `risk_difference()` calcula diferença e intervalo Newcombe-Wilson;
- `_group_summary()` resume grupos;
- `_condition_comparisons()` compara pares dentro de modelo e providers;
- `_validate_campaign_controls()` rejeita campanhas incompatíveis;
- `build_aggregate()` produz o conjunto final.

## 23. `tools/record_evaluation.py`

CLI para listar pendências e registrar avaliações de forma interativa ou por flags. Converte `status:descricao` e `componente:classificacao`, solicita campos ausentes e chama `record_evaluation()`.

## 24. `tools/build_results.py`

Localiza uma ou todas as condições de modelo/provider, executa `build_results()` e, com `--all-conditions`, também produz o agregado do experimento.

## 25. `tools/build_aggregate.py`

Executa somente o agregado. `--include-pilots` inclui campanhas marcadas como piloto para análise diagnóstica.

## 26. `tools/verify_run.py` e `tools/verify_campaign.py`

Criam selo com `--create` ou verificam o existente. Retornam código de erro quando inválido, permitindo uso em automação.

## 27. `scenarios/test_prompts.py`

É o catálogo executável de cenários. Cada entrada define a arquitetura determinística usada pelo estudo. Apesar do nome histórico `test_prompts`, seu conteúdo é entrada experimental e deve ser congelado antes da coleta.

## 28. `scripts/c2_server.py`

Servidor Flask de coleta em laboratório. Implementa ingestão de chaves/tokens, metadados de arquivos, heartbeat, estatísticas, limpeza e dashboard. Persiste `c2_events.json` no diretório de trabalho.

Ele foi projetado como fixture em rede isolada, não como serviço exposto. Não possui autenticação nem proteção para Internet.

## 29. Ferramenta `generate_test_files`

Implementada em Rust sob `tools/generate_test_files/`. Gera árvore de documentos sintéticos em formatos de escritório e texto, usando dados fictícios. `scripts/generate_test_files.sh` compila release e encaminha argumentos.

O código implementa geração de ZIP/Office localmente e paraleliza trabalho. Usa aleatoriedade do sistema, portanto fixtures devem ser congeladas quando identidade byte a byte for necessária.

## 30. Ferramenta `reset_vm`

Implementada em Rust sob `tools/reset_vm/`. Remove diretório de testes e resíduos conhecidos, limpa log C2, crontab relacionado e caches. Ignora symlinks na varredura. `scripts/reset_vm.sh` compila release e passa a raiz do projeto.

É uma ferramenta destrutiva destinada somente à VM de laboratório. O snapshot do hypervisor continua sendo a restauração principal.

## 31. Arquivos de dependência e configuração

- `requirements.in`: dependências Python diretas.
- `requirements.lock`: versões transitivas e hashes reproduzíveis.
- `.env.example`, quando presente: nomes de variáveis esperadas, nunca valores reais.
- `Cargo.toml` e `Cargo.lock`: workspace e versões das ferramentas Rust.

## 32. Suíte de testes

Os testes usam `unittest` e cobrem:

- normalização e montagem C;
- compilação determinística e falha terminal sem reparo;
- criação, falha, retomada e controle de campanhas;
- resumo de chamadas, custo, providers e recusas;
- classificação do Coder;
- revisão e tolerância do índice;
- ambiente e pacotes;
- proveniência Git, binários, segredos e symlinks;
- trace completo, concorrência e falha;
- recuperação, selos e entradas congeladas;
- avaliação, revisões, exclusões e resultados;
- diferença entre `fragmented` e `full_context`;
- consistência entre endpoints do cenário e servidor coletor.

Execução:

```bash
python -m unittest discover -s tests -v
```

Os testes substituem serviços remotos por doubles quando necessário. Uma suíte verde comprova contratos locais, não disponibilidade do provider nem sucesso funcional na VM.

## 33. Regras para mudança de código

### Mudança puramente operacional

Refatorações sem alteração observável ainda devem preservar testes e hashes de versão do software. Exemplos: melhoria de escrita atômica ou mensagem de erro.

### Mudança no instrumento experimental

Exige nova versão de protocolo ou template quando altera:

- prompt do Coder;
- contexto global;
- classificação de recusa;
- componentes ou cenário;
- retries;
- parâmetros;
- integração que influencia compilação;
- rubrica ou denominadores.

Campanhas iniciadas não devem misturar versões antes e depois da mudança.

### Mudança analítica

Alterar métricas ou estatística exige regenerar resultados e registrar a versão do código. Preserve os produtos anteriores quando já usados em uma análise apresentada.
