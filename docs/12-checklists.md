# Checklists operacionais

## 1. Antes de alterar o pipeline

- [ ] Identificar se a mudança é operacional, experimental ou analítica.
- [ ] Ler os testes relacionados.
- [ ] Confirmar que nenhuma campanha oficial em andamento será misturada com a nova versão.
- [ ] Atualizar versão de template, protocolo ou rubrica se a mudança afetar o instrumento.
- [ ] Executar a suíte completa.
- [ ] Atualizar a documentação correspondente.

## 2. Antes do piloto

- [ ] Criar ambiente Python a partir de `requirements.lock`.
- [ ] Confirmar GCC, `pkg-config`, OpenSSL, libcurl e OpenCode.
- [ ] Configurar credencial sem colocá-la no repositório.
- [ ] Conferir modelo e provider disponíveis.
- [ ] Revisar cenário, componentes, protótipos, `config.h` e `main.c`.
- [ ] Criar protocolo específico do piloto.
- [ ] Definir `status: frozen` após revisão.
- [ ] Conferir hipótese e métrica primária.
- [ ] Conferir exclusões e regra de parada.
- [ ] Conferir rubrica.
- [ ] Preparar duas VMs e rede interna.
- [ ] Criar snapshots limpos.
- [ ] Preencher JSON do ambiente de VM.
- [ ] Preparar fixtures exclusivamente sintéticas.
- [ ] Executar testes automatizados.

## 3. Validação do piloto

- [ ] As duas condições foram criadas.
- [ ] `stimulus_sha256` coincide entre condições.
- [ ] `full_context_sha256` coincide entre condições.
- [ ] `context_mode` difere como planejado.
- [ ] Prompts fragmentados não contêm contexto global.
- [ ] Prompts completos contêm arquitetura, configuração e integração.
- [ ] Modelo e provider observados foram registrados.
- [ ] Calls, eventos, manifestos e resultados existem.
- [ ] Falha individual não interrompeu o lote.
- [ ] `--resume` completou somente lacunas em um teste controlado.
- [ ] Transporte para a VM funcionou.
- [ ] Snapshot foi restaurado por run.
- [ ] Evidências foram copiadas e hashadas.
- [ ] Avaliação revisionada funcionou.
- [ ] CSVs e agregado foram regenerados.
- [ ] Selos foram verificados.
- [ ] Nenhum segredo apareceu nos artefatos.

## 4. Antes da campanha oficial

- [ ] Incorporar ao protocolo apenas mudanças decididas no piloto.
- [ ] Usar novo `experiment_id` ou versão coerente.
- [ ] Definir exatamente 50 réplicas por condição, se esse é o plano.
- [ ] Confirmar que `--all-conditions` resultará em 100 runs para duas condições.
- [ ] Fixar modelo e provider.
- [ ] Fixar `temperature`, `top_p`, `seed` e `max_tokens`.
- [ ] Congelar protocolo e rubrica.
- [ ] Confirmar worktree e commit que serão usados.
- [ ] Confirmar espaço em disco e orçamento de API.
- [ ] Confirmar que `results/` não contém campanha com a mesma identidade.
- [ ] Salvar logs da revisão metodológica.
- [ ] Não examinar resultados parciais para mudar critérios.

## 5. Durante a geração oficial

- [ ] Não editar arquivos dentro das runs.
- [ ] Monitorar `campaign.json` e eventos.
- [ ] Monitorar rate limits, saldo e disco.
- [ ] Preservar falhas.
- [ ] Em interrupção, usar `--resume`.
- [ ] Não repetir manualmente uma réplica terminal.
- [ ] Registrar incidentes externos com horário.
- [ ] Confirmar que nenhum binário é executado no host.

## 6. Após a geração

- [ ] Status de cada campanha é coerente.
- [ ] Contagem iniciada corresponde às réplicas registradas.
- [ ] Falhas possuem `result.json` ou registro de inicialização.
- [ ] Não existem réplicas duplicadas.
- [ ] Cada run possui condição e modo corretos.
- [ ] Hashes dos controles coincidem entre condições.
- [ ] Providers observados foram revisados.
- [ ] Custos indisponíveis permanecem `null`.
- [ ] Selos de run são válidos.
- [ ] Campanha foi copiada para armazenamento seguro.

## 7. Antes de cada teste na VM

- [ ] Identificar `run_id`, campanha, condição e réplica.
- [ ] Verificar selo da run.
- [ ] Restaurar snapshot da VM de execução.
- [ ] Restaurar snapshot da VM coletora.
- [ ] Confirmar rede interna sem Internet.
- [ ] Confirmar ausência de rota para o host.
- [ ] Limpar ou restaurar estado do coletor.
- [ ] Restaurar a mesma fixture sintética.
- [ ] Confirmar hash ou inventário da fixture.
- [ ] Preparar captura de stdout, logs e rede.
- [ ] Não montar pastas pessoais do host.

## 8. Após cada teste na VM

- [ ] Parar o processo observado.
- [ ] Exportar `c2_events.json`.
- [ ] Exportar stdout e stderr.
- [ ] Exportar inventário antes/depois.
- [ ] Exportar capturas e logs definidos na rubrica.
- [ ] Calcular ou conferir hashes no transporte.
- [ ] Registrar o ambiente da VM.
- [ ] Aplicar todos os checks da rubrica.
- [ ] Classificar o resultado funcional.
- [ ] Registrar componentes quando aplicável.
- [ ] Decidir inclusão conforme critérios prévios.
- [ ] Justificar toda exclusão.
- [ ] Registrar avaliação pela ferramenta.
- [ ] Conferir `manual.json` e evidências copiadas.
- [ ] Restaurar snapshots antes da próxima run.

## 9. Antes da consolidação

- [ ] Listar pendências em todas as condições.
- [ ] Resolver avaliações incorretas criando nova revisão.
- [ ] Não editar a revisão vigente manualmente.
- [ ] Confirmar que exclusões têm justificativa.
- [ ] Confirmar que `environment_error` não foi tratado como falha funcional.
- [ ] Confirmar que recusas e falhas do modelo continuam incluídas conforme protocolo.
- [ ] Verificar selos.

## 10. Depois da consolidação

- [ ] Conferir `runs.csv` linha por linha em amostra aleatória.
- [ ] Comparar contagens com `campaign.json`.
- [ ] Conferir denominadores de cada taxa.
- [ ] Conferir `null` versus zero.
- [ ] Conferir intervalos e ordem A/B das diferenças.
- [ ] Conferir que pilotos foram excluídos.
- [ ] Conferir `experimental_controls.comparable`.
- [ ] Verificar `campaign_seal.json`.
- [ ] Preservar `provenance.json`.
- [ ] Registrar commit do código analítico.

## 11. Antes de escrever resultados no artigo

- [ ] Declarar exatamente o pipeline de componentes, sem Sanitizer ou Planner.
- [ ] Explicar que ambas as condições usam chamadas por componente.
- [ ] Definir fragmentação como visibilidade local.
- [ ] Informar cenário, modelos, providers e período.
- [ ] Informar número planejado e efetivo por condição.
- [ ] Publicar contagens de falha e exclusão.
- [ ] Definir recusa terminal e qualquer recusa.
- [ ] Separar geração, compilação e função.
- [ ] Informar denominadores.
- [ ] Reportar intervalos de confiança.
- [ ] Reportar limitações do classificador.
- [ ] Reportar ausência de cegamento, se aplicável.
- [ ] Reportar mudanças ou indisponibilidade de provider.
- [ ] Não tratar custo ausente como zero.
- [ ] Referenciar commit, protocolo e hashes.

## 12. Congelamento final

- [ ] Todas as campanhas oficiais estão concluídas.
- [ ] Todas as runs elegíveis estão avaliadas.
- [ ] Todos os agregados foram regenerados uma última vez.
- [ ] Todos os selos são válidos.
- [ ] O repositório não contém credenciais.
- [ ] O dataset público foi revisado separadamente.
- [ ] Commit final foi identificado.
- [ ] Cópia somente leitura foi criada.
- [ ] Hashes principais foram guardados fora da cópia de trabalho.
- [ ] Documentação corresponde ao código usado na análise.
