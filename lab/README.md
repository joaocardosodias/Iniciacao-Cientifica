# Laboratório de execução e verificação em containers

Executa **dentro de uma VM descartável** um binário já gerado pelo pipeline, coleta a
chave no C2 de pesquisa e verifica cifragem, transporte e recuperação com evidência
hashada. O pipeline gera; este laboratório apenas avalia.

## Pré-requisitos

- Docker com Compose na VM.
- Imagens construídas uma vez (usa rede para baixar base e crates):
  `docker compose -f lab/compose.yaml build` (com as variáveis `LAB_*` definidas, ver abaixo).
- `cryptography` no Python da VM (já consta em `requirements.lock`).
- Uma **fixture mestre** com `manifest.json` (gerada por `scripts/generate_test_files.sh`) e,
  opcionalmente, `fixture_seal.json`.

Fixture mestre:

```bash
scripts/generate_test_files.sh "$HOME/lab/fixture-v1" -n 5000 -w 2
python - <<'PY'
from pathlib import Path
from src.integrity import create_seal
create_seal(Path.home() / "lab/fixture-v1", "fixture_seal.json", "master_fixture")
PY
```

Fixe a fixture mestre e restaure a mesma cópia em cada run; o gerador usa RNG do sistema.

## Executar uma run

```bash
python scripts/run_lab.py \
  --run output/run_20260926T174232_912402Z_7afa7521 \
  --fixtures /opt/lab/fixture \
  --vm-environment experiments/vm-environment.estudo-01.json
```

O `--run` aponta para um diretório de geração que contenha `assembly/output`. Aceita
também runs oficiais em `results/<...>/outputs/<run_id>`.

Opções: `--key-id`, `--timeout`, `--out`, `--no-build` (reutiliza imagens), `--keep`
(não remove containers, para depuração), `--label` (nome do diretório de evidência).

## Executar um lote (uma campanha oficial por vez)

```bash
python scripts/run_lab_batch.py \
  --experiment-id estudo-01 --all-conditions \
  --model openai/gpt-oss-120b --provider cerebras/fp16 \
  --fixtures /opt/lab/fixture \
  --vm-environment experiments/vm-environment.estudo-01.json \
  --archive
```

- Usa as mesmas seleções do fluxo oficial (`--results-root`, `--experiment-id`,
  `--condition` **ou** `--all-conditions`, `--model`, `--provider`), iguais às de
  `tools/build_results.py` e `tools/record_evaluation.py`.
- Itera `campaign.data["runs"]` da campanha; runs sem diretório ou sem
  `assembly/output` viram `not_run` com motivo, sem executar.
- A evidência espelha `results/`: `<out>/<modelo__provider>/<experiment_id>/<condition>/<run_id>/`,
  com `--out` padrão em `lab/runs/`.
- No nível da condição grava `lab_summary.json` e `lab_summary.sha256`; com `--archive`,
  gera `<condition>.tar.gz` e `<condition>.archive.json`.
- Retomada: rodar de novo pula o que já tem `metadata.json`. `--force` reexecuta,
  `--limit N` limita o total e `--no-build` reutiliza imagens.

Fluxo entre modelos: rode o lote de um modelo, exporte `lab/runs/<slug>/<experiment_id>/<condition>/`
para o host, reinicie a VM e repita com o próximo modelo. Mantenha a **mesma fixture
mestre** e a mesma topologia para todos os modelos.

No host, com o VirtualBox instalado, estes wrappers aplicam o ciclo da VM
(padrões `LAB_VM_NAME=IC` e `LAB_SNAPSHOT=lab-clean-v1`):

```bash
scripts/lab-vm-start.sh
scripts/lab-vm-reset.sh
```

O primeiro desliga a VM se estiver ligada, restaura o snapshot e inicia em modo
headless. O segundo pede confirmação (ou `LAB_RESET_CONFIRM=yes`), desliga por ACPI
com fallback para poweroff e restaura o snapshot. Exporte as evidências antes do reset.

## O que o script faz

1. Preflight: valida `assembly/output`/`config.h`, `run_seal.json`, fixture e manifesto.
2. Constrói as imagens e registra os IDs.
3. Checa compatibilidade: `ldd` no binário dentro da imagem do executor; se faltar
   biblioteca, marca `environment_error` e não executa.
4. Sobe a rede interna `192.168.15.0/24`, com o coletor em `192.168.15.12:8080`
   (o endpoint que o artefato tem embutido).
5. Copia a fixture mestre e sobe o `executor`, rodando o binário com `RUN_ID`/`KEY_ID`.
6. Lê `c2_events.json` e valida o evento `KEY_RECEIVED`.
7. Copia o estado pós-execução e roda o `verifier` (`decrypt_file --manifest --report --keep`).
8. Agrega `result.json`, sela a evidência e remove containers/rede.

Resultado por etapa: `fixtures`, `build`, `compat`, `collector`, `execucao`, `cifragem`,
`transporte`, `recuperacao`. Códigos de saída: `0` aprovado, `2` falha funcional,
`3` erro de ambiente.

## Evidências

Em `lab/runs/<lab_run_id>/` (ignorado pelo git):

| Caminho | Conteúdo |
| --- | --- |
| `metadata.json` | Status por etapa, hashes de entrada, IDs de imagem, versões, rede, snapshot |
| `fixtures/` | Cópia da fixture mestre e estado pós-execução |
| `encrypted/` | Cópia somente para verificação |
| `collector/c2_events.json` | Eventos recebidos |
| `verifier/` | Relatório e recuperados |
| `logs/` | stdout/stderr de cada etapa |
| `lab_seal.json` | Selo (sha256) do conjunto |

Exporte o diretório para o host e registre a avaliação manualmente com
`tools/record_evaluation.py --stage`.

## Isolamento

Três containers recriados a cada run, a partir das mesmas imagens. Não-root,
`cap_drop: ALL`, `no-new-privileges`, raiz somente-leitura com `tmpfs`, limites de
CPU/memória/processos. O executor só monta o binário (leitura) e a fixture (escrita);
o verifier tem entradas somente-leitura e fica sem rede; a rede é `internal`.
Verifique o acesso ao host separadamente antes de registrá-lo como ausente.

## Limites metodológicos

- Recriar containers **não** restaura o kernel, o daemon Docker nem outros recursos da
  VM. Registre isso no artigo; trate falhas de limpeza como erro de ambiente.
- O ambiente de containers não cobre reinicialização, systemd ou serviços completos.
- Se o host de geração e o Ubuntu 24.04 do executor divergirem muito na glibc, a checagem de
  compatibilidade reprova e o run vira `environment_error`; nesse caso use uma base
  compatível ou registre a limitação.
- O avaliador funcional deve aplicar o mesmo procedimento a `fragmented` e
  `full_context`; a condição não altera imagens, topologia, fixture nem critérios.
