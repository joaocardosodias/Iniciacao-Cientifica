# Falhas, recuperação e integridade

## 1. Princípio

Uma falha não é lixo operacional. Em um experimento de geração, erro de API, recusa, fonte inválida, falha de compilação, interrupção e erro ambiental são informações. O sistema tenta sempre deixar um estado terminal legível e impedir que uma pasta parcial seja interpretada como sucesso.

## 2. Classes de falha

### Antes da run

- argumento inválido;
- cenário inexistente;
- protocolo não congelado;
- divergência de controles;
- preflight reprovado;
- campanha duplicada.

Essas falhas podem ocorrer antes de criar uma run. A campanha registra falha de preflight quando já existe.

### Inicialização da run

- impossibilidade de criar diretórios;
- erro na proveniência;
- erro ao escrever manifesto.

Quando um diretório de run foi criado, o código tenta produzir um resultado `initialization_failed` ou recuperar a pasta como órfã.

### Geração

- credencial ou endpoint inválido;
- rate limit persistente;
- erro HTTP não recuperável;
- filtro do provider;
- resposta vazia;
- recusa textual;
- resposta inválida após tentativas;
- exceção em thread de componente.

Arquivos de chamada e eventos preservam o ponto de falha.

### Montagem

- ausência de funções ligáveis;
- erro do GCC;
- binário ausente;
- retorno não zero da única compilação GCC.

O diagnóstico fica em `assembly/`.

### Avaliação

- snapshot incorreto;
- rede inadequada;
- fixture ausente;
- evidência insuficiente;
- erro ambiental.

Esses casos pertencem à avaliação e não devem alterar `result.json`.

## 3. Escrita atômica

JSONs de estado importantes usam um arquivo temporário no mesmo diretório e `os.replace`. Isso evita expor um arquivo de destino parcialmente escrito em condições normais de filesystem. A implementação atual não executa `fsync` nesses JSONs, portanto a substituição atômica não equivale a garantia de persistência física após queda de energia.

Logs JSONL usam append, lock, `flush` e `fsync`; os CSVs consolidados também são sincronizados antes da substituição. A append-only preserva histórico, mas uma queda no meio de uma escrita de baixo nível ainda pode deixar a última linha incompleta. Ferramentas de auditoria devem tratar a última linha inválida como sinal de interrupção.

## 4. Interrupções por sinal

`RunGuard` instala handlers para SIGINT e SIGTERM somente quando permitido. Ao receber sinal:

1. registra `run.interrupted`;
2. finaliza o trace como `interrupted`;
3. levanta `RunInterrupted`;
4. a campanha registra a réplica e muda para `interrupted`;
5. os handlers anteriores são restaurados.

SIGKILL, queda de energia e encerramento abrupto não podem ser interceptados. Esses casos dependem da recuperação na próxima execução.

## 5. Proteção `atexit`

Se o processo termina normalmente pelo runtime, mas a run ainda não foi finalizada, o callback tenta marcá-la como `abandoned`. Esse caminho cobre saídas inesperadas que ainda executam handlers de encerramento.

Não cobre término forçado que impede callbacks.

## 6. Detecção de processo vivo

`process_alive(pid)` usa `os.kill(pid, 0)`:

- `ESRCH` indica processo inexistente;
- `EPERM` indica processo existente sem permissão;
- sucesso indica processo vivo.

PID pode ser reutilizado pelo sistema. A verificação de hostname e o uso próximo no tempo reduzem, mas não eliminam, essa possibilidade.

## 7. Recuperação de run stale

`recover_run()` só converte uma run `running` quando:

- o manifesto possui PID e hostname;
- o hostname é a máquina atual;
- o processo não está vivo.

Runs de outro host são ignoradas para evitar que uma montagem de filesystem compartilhado declare morto um processo remoto. Runs sem metadados de processo antigos também são deixadas intactas.

Quando elegível, a recuperação:

- reabre `events.jsonl` sem truncar;
- calcula duração aproximada;
- resume chamadas existentes;
- grava `result.json` como `abandoned` e `recovered: true` se ele não existe;
- atualiza o manifesto com bloco de recuperação;
- emite `run.recovered`;
- atualiza o índice, tolerando falha;
- sela a run.

Se `result.json` já existe, ele não é sobrescrito; o estado é reconciliado.

## 8. Recuperação de run órfã

Uma pasta `run_*` sem `manifest.json` é órfã. `recover_orphan_run()` cria registros mínimos com status `initialization_failed`, infere a réplica do sufixo quando possível, indexa e sela.

Isso impede que diretórios parcialmente criados desapareçam das contagens. Como a identidade disponível é limitada, campos desconhecidos permanecem nulos.

## 9. Varredura

`recover_stale_runs(output_root)` percorre diretórios `run_*`, trata órfãos, recupera manifestos `running` elegíveis e chama `index_existing_runs()`. A varredura ocorre antes de uma nova run no mesmo root.

Em campanhas grandes, essa verificação adiciona custo de inicialização. Em troca, reduz lacunas de índice e detecta restos de interrupções anteriores.

## 10. Reconciliação da campanha

`Campaign.reconcile()` examina `outputs/`, relaciona diretórios por réplica e atualiza a lista de runs. Réplicas duplicadas são rejeitadas. Contagens são recalculadas a partir dos registros, não apenas incrementadas cegamente.

`pending_replicates()` devolve a diferença entre `1..planned_replicates` e réplicas já registradas. É a base do `--resume`.

Uma réplica que falhou mas foi registrada não é ausente e não será reexecutada. Isso preserva a falha como observação. `--resume` completa lacunas; não repete desfechos ruins.

## 11. Estados de campanha

Estados relevantes incluem:

- `running`;
- `preflight_failed`;
- `interrupted`;
- `generation_completed`;
- estados de avaliação completa ou parcial atualizados por `refresh_evaluations()`.

`generation_completed` significa que o loop chegou ao fim, não que todas as runs tiveram sucesso. Consulte contagens de concluídas e falhas.

## 12. Índice como subsistema não crítico

Uma run pode terminar e salvar `result.json` antes da escrita em `experiments.jsonl`. Se o índice falha, o erro vira aviso. O resultado terminal não é revertido.

Essa decisão prioriza o artefato primário. Uma futura inicialização tenta reindexar runs existentes. O mesmo princípio se aplica à recuperação.

## 13. Selos de integridade

`create_seal()` percorre arquivos do escopo, calcula tamanho e SHA-256, ordena registros e calcula um hash combinado. `verify_seal()` compara:

- arquivos ausentes;
- arquivos modificados;
- arquivos inesperados;
- hash combinado.

### Selo da run

Exclui `run_seal.json`, metadados de sistema e `evaluation/`. Assim, o resultado da geração pode ser selado antes da avaliação.

### Selo da campanha

Inclui estado consolidado da campanha e é recriado por `build_results()`. Uma avaliação nova exige reconstrução.

## 14. Comandos de verificação

```bash
python tools/verify_run.py <diretorio-da-run>
python tools/verify_campaign.py <diretorio-da-campanha>
```

Saída válida termina com status positivo. Em divergência, o comando retorna código não zero e lista diferenças.

`--create` existe para criar um selo explicitamente:

```bash
python tools/verify_run.py <diretorio-da-run> --create
python tools/verify_campaign.py <diretorio-da-campanha> --create
```

Não use `--create` para ocultar uma alteração inesperada. Primeiro investigue, documente a razão e só então regenere produtos autorizados.

## 15. O que os selos não garantem

- Não são assinaturas digitais.
- Não provam autoria.
- Não impedem modificação.
- Não substituem backup imutável.
- Não provam que o binário foi executado.
- Não validam semanticamente a evidência.

Eles detectam divergência em relação ao estado selado, desde que o selo original seja confiável.

## 16. Procedimento após interrupção

1. Não apague a pasta parcial.
2. Preserve stdout do terminal, se disponível.
3. Execute novamente com `--resume` para campanhas.
4. Confira eventos de recuperação.
5. Confirme que a réplica interrompida foi registrada ou permanece ausente.
6. Não force reexecução de uma réplica já terminal.
7. Verifique contagens no manifesto.
8. Ao fim, regenere resultados e selos.

## 17. Procedimento diante de selo inválido

1. Pare a consolidação.
2. Salve a saída da verificação.
3. Compare arquivos listados como ausentes, modificados ou extras.
4. Verifique histórico Git e timestamps.
5. Determine se foi uma avaliação legítima, produto regenerado ou alteração indevida.
6. Se a alteração era autorizada, reconstrua pelo comando de origem.
7. Se não era, restaure de uma cópia confiável e documente o incidente.
8. Não publique métricas derivadas enquanto a origem estiver ambígua.

## 18. Backup e transporte

Git oferece histórico e transporte, mas arquivos grandes e binários podem exigir política própria. Para uma coleta definitiva, mantenha ao menos:

- repositório remoto com acesso controlado;
- cópia somente leitura ou snapshot do estado final;
- hashes dos commits e selos fora da árvore principal;
- registro de quem realizou transporte e avaliação.

Antes de clonar para a VM, confira o commit. Depois de copiar evidências de volta, confirme seus hashes antes de restaurar a VM.
