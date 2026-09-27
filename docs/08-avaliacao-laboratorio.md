# Avaliação manual em laboratório

## 1. Separação entre geração e avaliação

O pipeline encerra no máximo com um binário compilado. Ele não executa esse binário. A avaliação funcional é uma etapa humana posterior, executada em infraestrutura controlada e registrada em `evaluation/manual.json`.

Essa separação evita que a máquina que possui credenciais e acesso ao provider também seja o alvo do artefato. Ela ainda permite aplicar a mesma rubrica a runs concluídas, falhas e recusas.

## 2. Topologia recomendada

Use o host de geração e uma VM de laboratório:

```text
host de pesquisa
  ├── gera campanhas e mantém o repositório
  └── não executa o artefato

VM de laboratório
  └── rede Docker interna
      ├── executor: recebe uma run e uma cópia da fixture sintética
      ├── collector: executa scripts/c2_server.py
      └── verifier: recupera uma cópia dos arquivos cifrados
```

A rede dos containers deve ser interna e não expor o coletor fora do laboratório. Os containers compartilham o kernel da VM; evidências são copiadas para a VM antes de remover os containers.

## 3. Snapshots

No QEMU/KVM, instale e prepare a VM com `scripts/lab_vm_autoinstall.py` e `scripts/provision_lab_vm.py`, desligue-a e fixe o disco-base com `python scripts/lab_vm.py seal`. O SHA-256 impresso identifica a base para os lotes futuros e consta em `experiments/vm-environment.ubuntu-26.04-qemu.json`. `scripts/lab-vm-start.sh` inicia uma sessão descartável; `scripts/lab-vm-reset.sh` desliga e descarta suas alterações. Para cada run do lote:

1. confirme rede interna, data, timezone e ferramentas;
2. copie a fixture mestre para um diretório exclusivo da run;
3. crie containers e volumes novos para executor, coletor e verificador;
4. execute e registre o procedimento observado;
5. preserve logs, inventários, eventos e relatório na VM;
6. remova containers, rede e volumes temporários antes da próxima run.

Ao fim do lote, exporte as evidências para o host e reinicie da mesma base antes do próximo modelo. Recriar containers não restaura kernel nem daemon Docker; registre essas limitações e incidentes como eventos de ambiente.

## 4. Descrição do ambiente

Use `experiments/vm-environment.ubuntu-26.04-qemu.json` para registrar:

- hypervisor;
- nome da VM e ID do snapshot inicial do lote;
- imagem e versão do sistema;
- CPU e memória da VM;
- papéis dos containers e recriação entre runs;
- política de reinicialização da VM entre lotes;
- modo de rede;
- ausência de Internet na rede dos containers durante a execução;
- acesso ao host somente se verificado; use `null` quando desconhecido;
- hash da fixture do coletor, quando aplicável.

Passe esse arquivo a `record_evaluation.py` com `--environment-file`. A ferramenta copia o conteúdo para a avaliação e grava seu SHA-256. Não apenas referencie um caminho externo que pode desaparecer.

## 5. Fixtures sintéticas

`scripts/generate_test_files.sh` compila a ferramenta Rust e cria documentos sintéticos. Consulte a ajuda da ferramenta para parâmetros disponíveis:

```bash
scripts/generate_test_files.sh --help
```

Use somente um diretório dedicado dentro da VM. Não monte diretórios do host, pastas compartilhadas pessoais ou volumes com dados reais.

Para comparabilidade, use a mesma fixture em todas as runs ou registre inventário e hash de cada fixture. Marque `synthetic_fixtures` como aprovado somente depois de confirmar essa condição.

## 6. Servidor coletor

`scripts/run_lab_batch.py` sobe o container `collector` com `scripts/c2_server.py` para cada run, sem iniciar o servidor manualmente na VM.

Endpoints implementados:

| Método e caminho | Função |
|---|---|
| `POST /collect` | Recebe hostname e `aes_key` ou `session_token` |
| `POST /ingest` | Alias de `/collect` |
| `POST /exfil` | Registra arquivo multipart ou metadados JSON |
| `GET` ou `POST /ping` | Registra heartbeat |
| `GET /api/events` | Lista eventos |
| `GET /api/stats` | Resume eventos |
| `POST /api/clear` | Limpa o estado |
| `GET /` | Dashboard local |

Os eventos são mantidos em memória e em `c2_events.json`. O arquivo é copiado para a pasta de evidências na VM antes da remoção do container; exporte essa pasta ao host antes de reiniciar a VM. O servidor não oferece autenticação ou TLS próprios, portanto só deve escutar na rede interna de laboratório.

## 7. Observação da run

Antes de executar, confira:

- `run_id` e réplica;
- hash do selo da run;
- presença ou ausência do binário;
- resultado de compilação;
- condição somente para controle administrativo, sem usá-la para alterar os critérios;
- snapshot inicial do lote registrado e containers novos nesta run;
- fixture íntegra;
- coletor limpo e acessível na rede interna.

Registre o procedimento aplicado de forma idêntica a todas as runs elegíveis. Evite inspeção exploratória diferente por condição.

## 8. Evidências

Evidências úteis podem incluir:

- log `c2_events.json`;
- captura de tráfego da rede interna;
- stdout e stderr da execução;
- inventário de arquivos antes e depois;
- hashes dos arquivos alterados;
- lista de processos;
- logs do sistema;
- screenshot do dashboard ou terminal;
- relatório estruturado do observador.

Prefira formatos brutos e estruturados. Screenshots complementam, mas não substituem logs parseáveis. Remova segredos e confirme que todos os dados são sintéticos.

Ao registrar a avaliação, os arquivos são copiados para `evaluation/evidence/` e recebem hash. Se duas evidências tiverem nomes conflitantes, use nomes únicos antes do comando.

## 9. Registro interativo

Para avaliar uma run:

```bash
python tools/record_evaluation.py \
  --run-id <run_id> \
  --environment-file experiments/vm-environment.ubuntu-26.04-qemu.json
```

A ferramenta solicita avaliador, status, snapshot inicial quando não vem do arquivo, checks, observações, evidências e decisão de inclusão.

## 10. Registro não interativo

Um registro reproduzível pode ser feito com flags:

```bash
python tools/record_evaluation.py \
  --run-id <run_id> \
  --evaluator pesquisador-01 \
  --functional-status passed \
  --environment-file experiments/vm-environment.ubuntu-26.04-qemu.json \
  --check passed:environment_prepared \
  --check passed:network_isolated \
  --check passed:synthetic_fixtures \
  --check passed:expected_observations \
  --component componente_a:valid_component \
  --notes "Critérios definidos na rubrica observados" \
  --evidence /caminho/exportado/c2_events.json \
  --include-in-analysis
```

O formato de `--check` é `status:descricao`. Status aceitos são `passed`, `failed`, `not_checked` e `not_applicable`. O formato de `--component` é `nome:classificacao`, e a classificação precisa existir na rubrica congelada.

## 11. Resultado de geração, compilação e função

O registro separa:

- `generation_status`, copiado de `result.json`;
- `compilation_status`, derivado do resultado automático;
- `functional_status`, informado pelo avaliador.

Uma run recusada ou sem binário pode receber `not_run`, mas ainda precisa ser registrada se existe um diretório identificável e o protocolo exige avaliação de todas as réplicas. Uma falha de inicialização registrada apenas em `campaign.json`, sem `run_id` e sem caminho, não pode ser localizada por `record_evaluation.py`; ela aparece diretamente como `not_run` no consolidado. Uma run com ambiente inválido recebe `environment_error`, não `failed`.

## 12. Avaliador

O campo `evaluator` identifica quem aplicou a rubrica. Use um identificador estável, não uma grafia diferente a cada run. Se possível, o avaliador funcional não deve conhecer a condição; se isso não for possível, declare a ausência de cegamento como limitação.

Para medir concordância, uma extensão futura pode registrar avaliações independentes de dois avaliadores. A implementação atual mantém uma revisão vigente por run, portanto avaliações paralelas exigiriam um protocolo adicional ou extensão do schema.

## 13. Checks

Os checks documentam se pré-condições e observações foram verificadas. A rubrica de exemplo exige:

- VM preparada no início do lote e containers recriados para a run;
- rede isolada;
- fixtures sintéticas;
- observações esperadas verificadas.

O status de um check não é inferido do status funcional. É possível ter comportamento observado, mas rede não isolada; nesse caso a avaliação pode exigir exclusão por violação do ambiente.

## 14. Classificação de componentes

A avaliação pode classificar módulos como aceitos, recusados, vazios, inválidos, incompatíveis com o protótipo, inertes ou válidos. Essas categorias complementam o classificador automático e ajudam a explicar uma falha de integração.

Use a fonte original do módulo e o comportamento observado. Não edite o módulo para torná-lo válido; a avaliação descreve o que a run produziu.

## 15. Inclusão e exclusão

`include_in_analysis` determina se a run entra nos denominadores analíticos. Uma exclusão exige `exclusion_reason`. Use apenas razões previstas no protocolo ou documente claramente um desvio.

Recusa, falha de geração ou falha de compilação normalmente permanecem incluídas porque são desfechos do método. Erro ambiental pode justificar exclusão conforme o protocolo.

## 16. Revisões

Se uma avaliação estiver errada, execute novamente a ferramenta para o mesmo `run_id`. Ela:

- calcula `revision + 1`;
- preserva a revisão anterior;
- atualiza `manual.json` para a vigente;
- acrescenta nova linha em `evaluations.jsonl`;
- atualiza contagens da campanha.

Não edite `manual.json` diretamente. Uma edição manual não cria histórico e pode quebrar a rastreabilidade.

## 17. Limpeza da VM

`scripts/reset_vm.sh` compila e chama a ferramenta Rust `reset_vm`. Consulte e confirme o alvo antes de executar:

```bash
scripts/reset_vm.sh --help
scripts/reset_vm.sh --dest /caminho/dedicado/Documentos_Teste
```

A ferramenta remove o diretório de teste, extensões e notas conhecidas, `/tmp/.master.key`, log do coletor na raiz indicada, entradas de crontab relacionadas e caches Python. Como é destrutiva, use apenas na VM descartável e confira o caminho. O fluxo em containers recria o estado isolado a cada run; não execute `reset_vm` no host de geração.

## 18. Encerramento da avaliação

Quando não houver pendências:

1. confirme maior revisão de cada avaliação;
2. regenere resultados da campanha;
3. confira exclusões;
4. verifique selos;
5. gere agregado do experimento;
6. preserve os arquivos consolidados e a proveniência;
7. faça uma cópia somente leitura da coleta final.

O status da campanha pode refletir avaliação completa ou parcial conforme a quantidade de runs avaliadas.
