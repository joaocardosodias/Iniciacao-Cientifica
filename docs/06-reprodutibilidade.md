# Reprodutibilidade

## 1. Definições usadas

Neste projeto:

- repetibilidade é executar novamente no mesmo contexto e obter uma distribuição compatível;
- reprodutibilidade é permitir que outra pessoa reconstrua o procedimento com entradas e ambiente registrados;
- replicabilidade é repetir o estudo com nova coleta e verificar se a conclusão se mantém.

Como o LLM é remoto e potencialmente não determinístico, igualdade bit a bit não é uma expectativa realista. O objetivo é tornar o procedimento e suas diferenças observáveis.

## 2. Camadas de controle

O projeto combina:

1. dependências Python travadas;
2. snapshot Git e hashes de fontes;
3. ambiente da máquina de geração;
4. protocolo e rubrica congelados;
5. cenário e intervenção congelados;
6. parâmetros de inferência persistidos;
7. provider fixado quando solicitado;
8. VMs e snapshots documentados;
9. evidências funcionais hashadas;
10. resultados regenerados por scripts.

Nenhuma camada isolada garante reprodução. A força está na composição.

## 3. Dependências Python

`requirements.in` declara dependências diretas:

- `cryptography`;
- `flask`;
- `openai`;
- `python-dotenv`;
- `PyYAML`;
- `requests`.

`requirements.lock` é gerado por resolução e contém versões transitivas e hashes. Para ambiente controlado, prefira instalar o lock com verificação de hashes:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
```

`requirements.in` permanece curto porque contém somente dependências diretas; as bibliotecas transitivas aparecem no lock. Alterar uma dependência direta exige regenerar o lock e executar os testes.

## 4. Dependências do sistema

O pipeline depende, conforme o cenário e o caminho de compilação, de:

- Python compatível;
- GCC;
- `pkg-config`;
- headers e bibliotecas de OpenSSL;
- headers e biblioteca libcurl;
- Git para snapshot completo de proveniência.

As ferramentas Rust de laboratório dependem de Cargo para compilação. O servidor de coleta depende de Flask.

Versões são capturadas quando detectáveis. A ausência de uma ferramenta crítica deve ser detectada pelo preflight oficial antes das chamadas remotas.

## 5. Preflight

`run_preflight()` verifica antes de uma campanha:

- presença de GCC e `pkg-config`;
- importação de bibliotecas Python essenciais;
- existência da variável de credencial adequada, sem ler seu valor para o relatório;
- compatibilidade do provider fixado com o gateway;
- completude do cenário;
- unicidade dos nomes de componentes;
- presença de `config.h` e `main.c`;
- permissão de escrita;
- espaço livre mínimo de 1 GiB;
- disponibilidade de bibliotecas nativas esperadas.

O resultado é salvo em `preflight.json` e referenciado pela campanha. A disponibilidade do modelo remoto não é comprovada localmente; ela só pode ser observada na chamada real.

## 6. Preparação do protocolo

Antes da coleta oficial:

1. copie `experiments/protocol.example.yaml` para um nome versionado;
2. substitua identificador, modelo, provider e parâmetros reais;
3. declare as duas condições e seus modos;
4. fixe o número de réplicas por condição;
5. declare hipótese e métrica primária;
6. declare exclusões e regra de parada;
7. registre snapshots e rede;
8. revise o documento antes de gerar resultados.

O arquivo fornecido ao comando é copiado para a campanha e hashado. Não edite a cópia congelada.

## 7. Preparação da rubrica

A rubrica precisa descrever critérios observáveis, não impressões gerais. Cada check deve ser testável e as classificações por componente devem ter semântica conhecida. O arquivo é validado, copiado e hashado.

Se a rubrica mudar depois do piloto, use uma nova versão e reinicie a coleta oficial. Misturar rubricas na mesma comparação invalida a equivalência.

## 8. Identidade do estímulo

O cenário é convertido em estrutura canônica. A ordem dos componentes faz parte da identidade. O hash combinado muda se descrição, protótipo, configuração, integração ou lista de componentes mudar.

As duas condições do mesmo experimento devem apresentar o mesmo `stimulus_sha256`. A diferença esperada está em `intervention_sha256`, pois o modo e a visibilidade diferem. O hash do conteúdo global completo deve ser comum, demonstrando qual arquitetura foi ocultada na condição fragmentada.

## 9. Parâmetros de inferência

O protocolo e a campanha registram:

- `temperature`;
- `top_p`;
- `seed`;
- `max_tokens`.

Ausência e valor explícito são diferentes. `null` pode significar que o provider escolheu o padrão. Para comparação rigorosa, declare explicitamente todos os parâmetros suportados. Não suponha que providers diferentes interpretam o mesmo parâmetro de forma idêntica.

## 10. Modelo e provider

Use o nome explícito do modelo e fixe o provider quando o gateway permitir. A campanha preserva o solicitado; as chamadas preservam o observado. Se o provider observado divergir ou ficar indisponível, isso deve aparecer na análise de qualidade e pode acionar um critério pré-registrado de exclusão.

Não combine campanhas de roteamentos diferentes como se fossem réplicas homogêneas. O agregador agrupa comparações por modelo e providers.

## 11. Ambiente de geração

A máquina que chama o LLM e compila os módulos recebe snapshot de:

- plataforma;
- Python;
- CPU;
- ferramentas externas;
- pacotes instalados;
- commit, branch, diff e fontes não rastreadas.

Idealmente, a coleta oficial começa em worktree limpa, commit identificado e ambiente criado do lock. O sistema suporta worktree suja porque a proveniência captura o diff, mas isso aumenta o trabalho de reconstrução.

## 12. Ambiente de avaliação

O ambiente funcional é outro domínio. Use pelo menos:

- VM de execução, que recebe a run e as fixtures;
- VM coletora, que executa o servidor de laboratório;
- rede interna sem Internet e sem rota para o host;
- snapshots limpos e identificados.

`experiments/vm-environment.example.json` oferece o contrato descritivo. Preencha hypervisor, nomes, IDs de snapshot, imagens, CPU, memória e propriedades de rede. O arquivo usado é copiado para cada avaliação e hashado.

## 13. Fixtures sintéticas

`scripts/generate_test_files.sh` compila e executa a ferramenta Rust `generate_test_files`. Ela cria uma árvore de documentos sintéticos em vários formatos. O conteúdo é gerado localmente e não deve conter dados pessoais reais.

Para máxima repetibilidade, registre:

- versão do gerador;
- quantidade solicitada;
- diretório de destino;
- hash ou inventário dos arquivos produzidos;
- momento da geração.

O gerador usa aleatoriedade do sistema, portanto conjuntos novos não são necessariamente idênticos. Se igualdade exata for necessária, crie uma fixture mestre, sele-a e restaure a mesma cópia em cada snapshot.

## 14. Restauração entre runs

O estado da VM precisa voltar a um baseline entre testes. A ferramenta `reset_vm` remove a pasta de fixtures, resíduos com extensões conhecidas, notas conhecidas, chave temporária, log C2, entradas de crontab associadas e caches.

Essa limpeza auxilia o laboratório, mas não substitui um snapshot do hypervisor. Um artefato pode modificar algo fora do conjunto conhecido. A prática recomendada é preservar evidências e restaurar o snapshot limpo para cada run.

## 15. Execução em lote e retomada

Campanhas executam réplicas sequenciais e preservam falhas. Interrupções não exigem recomeçar: `--resume` lê a campanha, reconcilia diretórios e executa somente números ausentes até o total original.

Retomada não permite alterar `--runs`; o total vem do manifesto. Entradas congeladas e parâmetros também vêm da campanha. Isso evita transformar uma interrupção em uma nova configuração experimental silenciosa.

## 16. Produtos regeneráveis

`runs.csv`, `summary.csv`, `summary.json`, `exclusions.csv` e agregados devem ser sempre recriados pelos scripts. Eles não são fontes primárias. As fontes são manifestos, resultados, avaliações e entradas congeladas.

Para confirmar reprodutibilidade analítica, execute novamente a consolidação e compare hashes ou conteúdo dos produtos. Mudança inesperada indica alteração de código analítico ou das entradas.

## 17. Requisitos para reprodução independente

Um pacote de reprodução deve incluir, conforme as restrições de segurança:

- commit ou snapshot completo do código;
- `requirements.lock`;
- protocolo e rubrica congelados;
- cenário canônico e intervenção;
- manifestos de campanha e runs;
- metadados de chamadas permitidos;
- descrição das VMs e rede;
- avaliações e evidências publicáveis;
- scripts de consolidação;
- selos e hashes;
- instruções operacionais e versão desta documentação.

Credenciais, arquivos `.env`, dados reais e artefatos perigosos não devem ser incluídos em pacote público sem governança específica.

## 18. Limites inevitáveis

- O backend do provider pode mudar sem aviso.
- A mesma seed pode não reproduzir a mesma resposta.
- Modelos comerciais podem ser atualizados sob o mesmo identificador.
- Custo pode não ser retornado.
- Provider de inferência observado pode não ser informado.
- Pacotes do host não capturam kernel e configuração integral.
- O snapshot descritivo da VM não é a imagem da VM.

Esses limites devem ser relatados, não ocultados. A documentação transforma incerteza em dado explícito.
