# Rastreabilidade e proveniência

## 1. Objetivo

Rastreabilidade responde “como este resultado foi produzido?”. Proveniência responde “com qual entrada, código, ambiente e serviço ele foi produzido?”. O projeto trata essas perguntas em várias camadas porque nenhum arquivo isolado é suficiente.

```text
protocolo e cenário congelados
        ↓
manifesto inicial + proveniência
        ↓
eventos e chamadas integrais
        ↓
módulos + montagem + compilação
        ↓
resultado terminal
        ↓
avaliação humana revisionada
        ↓
consolidação + selos
```

## 2. Identidade e tempo

Toda run recebe `run_id`, timestamps UTC e tempo decorrido monotônico no log de eventos. A campanha acrescenta experimento, condição e réplica. Essa combinação permite relacionar:

- linha no índice global;
- entrada em `campaign.json`;
- diretório da run;
- arquivos de chamada;
- resultado automático;
- avaliação manual;
- linha consolidada.

O timestamp civil registra quando algo ocorreu. `elapsed_seconds` permite ordenar e medir etapas mesmo se o relógio de parede sofrer ajuste. O número `seq` fornece ordem total dos eventos dentro da run.

## 3. EventLog append-only

`src/events.py` implementa `EventLog`. Cada emissão é serializada em uma única linha JSON sob `threading.Lock`, seguida por `flush()` e `os.fsync()`. Isso reduz a janela na qual uma queda deixaria eventos somente no buffer do processo.

Ao reabrir com `reset=False`, o logger lê a última sequência válida e continua a numeração. Isso é usado na recuperação para anexar `run.recovered` sem truncar o histórico anterior.

O log não é uma transação distribuída. Uma queda pode ocorrer entre a gravação de dois artefatos, por isso a recuperação e o manifesto também são necessários.

## 4. Eventos principais

As famílias de eventos incluem:

- `run.started`, `run.finished`, `run.interrupted`, `run.recovered`;
- início e término de camadas;
- `module.started`, `module.finished`, `module.failed`;
- `llm.call.started`, `llm.call.retry`, `llm.call.finished`;
- início e término da montagem.

Os campos de `data` variam por evento. O log serve para reconstruir a sequência, enquanto arquivos especializados preservam conteúdo extenso.

## 5. Manifesto progressivo

`manifest.json` é gravado atomicamente: uma versão temporária é sincronizada e substitui o destino. Ele registra o estado atual conhecido, não apenas o final. Estágios concluídos são adicionados à medida que o pipeline avança.

O manifesto e o event log são complementares:

- o manifesto responde ao estado atual e às identidades;
- os eventos respondem à cronologia;
- o resultado responde ao desfecho automático;
- as chamadas respondem ao conteúdo efetivamente trocado com a API.

## 6. Prova de chamada ao serviço

Cada arquivo em `calls/` contém os prompts enviados, a resposta recebida, identificadores retornados, modelo reportado, timestamps, uso e tentativas. Isso é a evidência principal contra a hipótese de que o processo foi apenas simulado localmente.

Ainda existem limites: um registro local não prova criptograficamente que um terceiro específico respondeu. Para uma auditoria científica razoável, a combinação de IDs da API, timestamps, metadados, uso, custo, respostas e logs é a evidência disponível. Se o provider oferecer logs exportáveis ou recibos assinados, eles podem ser anexados como evidência adicional sem substituir os registros atuais.

## 7. Hashes de conteúdo

SHA-256 é usado para relacionar conteúdos e detectar alterações:

- prompt original;
- prompts e respostas das chamadas;
- fontes congeladas;
- protocolo e rubrica;
- contexto global;
- arquivos de evidência;
- fontes do repositório;
- artefatos da run;
- snapshots das VMs;
- selos de run e campanha.

Um hash igual demonstra igualdade byte a byte sob o algoritmo, não equivalência semântica. Dois YAMLs semanticamente equivalentes com formatação diferente podem ter hashes de arquivo diferentes. Para estruturas geradas internamente, o projeto usa serialização canônica antes do hash quando apropriado.

## 8. Snapshot Git

`src/provenance.py` encontra a raiz Git e grava:

### `git_status.txt`

Saída de `git status --porcelain=v1 --branch`, mostrando branch, arquivos modificados, staged e não rastreados.

### `git.diff`

Diff contra `HEAD` com suporte a conteúdo binário. Ele registra mudanças rastreadas ainda não incorporadas ao commit.

### `untracked_files.json`

Lista arquivos não rastreados elegíveis com caminho, tamanho, hash e informação de armazenamento. Arquivos pequenos podem ser copiados para `provenance/untracked/`. Arquivos grandes recebem metadados, sem cópia integral.

### `source_hashes.json`

Calcula hashes para `pipeline.py`, módulos Python em `src/`, dependências, cenários Python, scripts Python, ferramentas Python, entradas experimentais e documentação. Um hash combinado ordenado identifica o conjunto.

Na implementação atual, os padrões de `source_hashes.json` não incluem fontes Rust, `Cargo.toml`, `Cargo.lock` nem wrappers `.sh`. Quando rastreados pelo Git, eles continuam vinculados ao commit e qualquer modificação aparece em status e diff, mas não participam do hash combinado de fontes. Essa limitação precisa ser considerada se as ferramentas de VM forem tratadas como parte do instrumento experimental.

O manifesto resume commit, branch, estado sujo, caminhos e hash combinado. Fora de um repositório Git, arquivos neutros são produzidos com campos indisponíveis em vez de interromper a run.

## 9. Proteção contra segredos na proveniência

Arquivos com nomes associados a credenciais, como `.env`, são marcados como possíveis segredos e não recebem cópia nem hash de conteúdo no inventário de não rastreados. Diretórios de saída são excluídos para evitar recursão e crescimento indefinido.

Esse filtro é uma defesa, não uma garantia universal. Credenciais salvas em um arquivo com nome inocente ainda podem ser capturadas. Antes de campanhas oficiais, o repositório deve ser revisado para remover segredos das fontes e arquivos não rastreados.

Valores das variáveis de ambiente não são gravados por `environment.py` ou `preflight.py`. O preflight apenas verifica se a variável necessária existe.

## 10. Ambiente de geração

`provenance/environment.json` registra informações como:

- sistema operacional e release;
- arquitetura e máquina;
- versão e implementação do Python;
- executável Python;
- CPU;
- versões detectáveis de GCC, OpenSSL e libcurl.

Ferramenta ausente recebe `null`. A coleta de proveniência não falha somente porque uma versão não pôde ser consultada.

`python_packages.json` lista todas as distribuições instaladas, ordenadas de forma estável. O manifesto contém apenas contagem e referências, evitando duplicar uma lista grande.

Esses arquivos descrevem a máquina da geração. O ambiente das VMs de execução e coleta é registrado separadamente durante a avaliação.

## 11. Resumo de chamadas

`src/call_summary.py` lê os arquivos de chamada e produz contagens, tokens, custo, modelos e providers observados. Ele não copia prompts nem respostas para `result.json`.

O resumo distingue:

- chamadas totais e concluídas;
- erros;
- recusas do provider e textuais;
- recusas explícitas e implícitas;
- respostas vazias, inválidas e guardas suspeitas;
- respostas aceitas;
- retries;
- tokens de entrada, saída e total;
- custo total quando informado;
- modelos, gateways e providers observados.

Se nenhum custo é informado, o valor é `null`. Custo explicitamente zero permanece zero. Essa distinção evita atribuir gratuidade onde há somente ausência de telemetria.

## 12. Índices revisionados

`experiments.jsonl`, `campaigns.jsonl` e `evaluations.jsonl` são append-only. Ao mudar um registro lógico, uma nova linha com `revision` maior é anexada. Um consumidor deve selecionar a maior revisão por chave.

Esse desenho preserva histórico e evita reescrita destrutiva. A exclusão manual de linhas quebraria a trilha. Concorrência local é protegida por lock de arquivo quando implementado e por verificação de duplicatas lógicas.

## 13. Rastreabilidade entre camadas

Para auditar uma réplica:

1. Localize a campanha pelo experimento, condição, modelo e provider.
2. Em `campaign.json`, encontre a entrada da réplica e seu `run_id`.
3. Abra `outputs/<run>/manifest.json` e confirme campanha, condição e hash de intervenção.
4. Compare protocolo, rubrica e cenário com `inputs/`.
5. Verifique `events.jsonl` para a cronologia.
6. Verifique cada chamada em `calls/` e compare hashes.
7. Compare módulos originais e normalizados.
8. Examine comando, stdout e stderr do GCC.
9. Leia `result.json` e o resumo de segurança.
10. Verifique `run_seal.json`.
11. Leia a maior revisão da avaliação e suas evidências.
12. Confirme a linha correspondente em `runs.csv`.

## 14. Granularidade e privacidade

O sistema deliberadamente mantém conteúdo integral dentro da pasta da run e apenas resumos nos índices. Isso reduz exposição acidental ao consultar arquivos globais, sem perder auditabilidade local.

Mesmo assim, as runs podem conter código, prompts e dados de interesse de segurança. O repositório remoto deve ter controle de acesso compatível, e a publicação de um dataset deve passar por revisão específica. Rastreabilidade não implica que todo artefato deva ser público.

## 15. Limites da rastreabilidade

- `fsync` reduz perda, mas não garante sobrevivência a todas as falhas de hardware.
- Hashes detectam mudança, mas não identificam o autor.
- Um selo recalculável não é assinatura digital.
- Metadados de provider dependem do que a API retorna.
- O ambiente remoto real do modelo não pode ser capturado integralmente pelo cliente.
- A proveniência do host não descreve automaticamente as VMs.
- Um arquivo de evento pode terminar com uma linha parcial após queda abrupta; leitores devem tolerar e reportar isso.
- Relógios de máquinas distintas podem não estar sincronizados; evidências devem registrar timezone e, se possível, NTP.

## 16. Regra para alegações científicas

Toda alegação quantitativa deve apontar para um produto regenerável; toda alegação sobre uma run deve apontar para evidência local; toda alegação sobre equivalência de condições deve apontar para os hashes dos controles. Quando a evidência não existe ou é `null`, o texto deve declarar indisponibilidade em vez de completar a lacuna por inferência.
