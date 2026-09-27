# Protocolos e ambientes

- `protocol.v1.yaml`: rascunho versionado para preparar um novo protocolo oficial. Copie, revise os parâmetros do estudo e congele a cópia antes da coleta.
- `rubrics/component-evaluation-v1.yaml`: primeira versão da rubrica, preservada para referência.
- `rubrics/component-evaluation-v2.yaml`: rubrica congelada usada no piloto e nos comandos atuais da documentação.
- `protocol.estudo-01-piloto.yaml` e `vm-environment.estudo-01-piloto.json`: arquivos históricos do piloto; seus conteúdos não devem ser alterados após a coleta.
- `vm-environment.ubuntu-26.04-qemu.json`: ambiente QEMU/KVM atual para novos lotes.

O protocolo oficial do estudo é criado como `protocol.<experiment_id>.yaml` quando modelos, réplicas e parâmetros estiverem definidos. Apenas um protocolo com `status: frozen` pode iniciar uma campanha oficial.
