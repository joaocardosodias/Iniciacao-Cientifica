#define _GNU_SOURCE

/*
 * API de orientação para recuperação após incidente de criptografia.
 *
 * document_recovery recebe um contexto opcional e preenche um plano ordenado
 * de recomendações. Os campos do contexto são ponteiros para strings
 * terminadas em NUL; o chamador mantém a propriedade e a validade dessas
 * strings. Campos nulos ou vazios são tratados como informações ausentes.
 *
 * A função não executa ações, acessa arquivos ou rede, nem altera o contexto.
 * As recomendações do plano são strings constantes e permanecem válidas
 * durante toda a execução do processo.
 *
 * Retorno: DOCUMENT_RECOVERY_OK se todos os campos do contexto foram
 * informados; DOCUMENT_RECOVERY_INCOMPLETE se algum campo está ausente ou
 * se o contexto é nulo; DOCUMENT_RECOVERY_INVALID_ARGUMENT se plan é nulo.
 * Em caso de contexto incompleto, missing_fields identifica os campos
 * ausentes e as recomendações continuam disponíveis.
 *
 * Limitação: esta API oferece orientações gerais. A equipe responsável deve
 * avaliar o incidente e decidir as ações específicas; a função não verifica
 * sistemas, evidências, backups ou recuperação.
 */
enum document_recovery_result {
    DOCUMENT_RECOVERY_OK = 0,
    DOCUMENT_RECOVERY_INCOMPLETE = 1,
    DOCUMENT_RECOVERY_INVALID_ARGUMENT = -1
};

enum document_recovery_missing_field {
    DOCUMENT_RECOVERY_MISSING_TIMESTAMPS = 1u << 0,
    DOCUMENT_RECOVERY_MISSING_SYSTEMS = 1u << 1,
    DOCUMENT_RECOVERY_MISSING_MESSAGES = 1u << 2,
    DOCUMENT_RECOVERY_MISSING_ACTIONS_TAKEN = 1u << 3
};

enum {
    DOCUMENT_RECOVERY_ACTION_COUNT = 10
};

struct document_recovery_context {
    const char *timestamps;
    const char *systems_affected;
    const char *observed_messages;
    const char *actions_already_taken;
};

struct document_recovery_plan {
    const char *actions[DOCUMENT_RECOVERY_ACTION_COUNT];
    unsigned int action_count;
    unsigned int missing_fields;
};

int document_recovery(const struct document_recovery_context *context,
                      struct document_recovery_plan *plan)
{
    unsigned int missing = 0;

    if (plan == 0) {
        return DOCUMENT_RECOVERY_INVALID_ARGUMENT;
    }

    if (context == 0) {
        missing = DOCUMENT_RECOVERY_MISSING_TIMESTAMPS |
                  DOCUMENT_RECOVERY_MISSING_SYSTEMS |
                  DOCUMENT_RECOVERY_MISSING_MESSAGES |
                  DOCUMENT_RECOVERY_MISSING_ACTIONS_TAKEN;
    } else {
        if (context->timestamps == 0 || context->timestamps[0] == '\0') {
            missing |= DOCUMENT_RECOVERY_MISSING_TIMESTAMPS;
        }
        if (context->systems_affected == 0 ||
            context->systems_affected[0] == '\0') {
            missing |= DOCUMENT_RECOVERY_MISSING_SYSTEMS;
        }
        if (context->observed_messages == 0 ||
            context->observed_messages[0] == '\0') {
            missing |= DOCUMENT_RECOVERY_MISSING_MESSAGES;
        }
        if (context->actions_already_taken == 0 ||
            context->actions_already_taken[0] == '\0') {
            missing |= DOCUMENT_RECOVERY_MISSING_ACTIONS_TAKEN;
        }
    }

    plan->actions[0] =
        "Isole os sistemas afetados da rede e dos recursos compartilhados, "
        "coordenando a ação com a equipe responsável; não apague nem altere "
        "arquivos.";
    plan->actions[1] =
        "Acione imediatamente a equipe de resposta a incidentes e siga os "
        "procedimentos internos aplicáveis.";
    plan->actions[2] =
        "Preserve arquivos criptografados, notas de resgate, registros e "
        "outros artefatos relevantes sem movê-los, renomeá-los ou modificá-los.";
    plan->actions[3] =
        "Registre horários, sistemas afetados, mensagens observadas e ações "
        "já realizadas; identifique como desconhecida qualquer informação "
        "que não esteja disponível.";
    plan->actions[4] =
        "Considere a preservação de memória e conexões ativas; deixe a coleta "
        "de evidências voláteis a cargo de pessoal qualificado.";
    plan->actions[5] =
        "Proteja os backups contra alteração ou exposição e solicite à equipe "
        "responsável que verifique se estão limpos antes de qualquer uso.";
    plan->actions[6] =
        "Restaure somente de fontes confiáveis e apenas em sistemas que a "
        "equipe responsável tenha avaliado como seguros.";
    plan->actions[7] =
        "Não execute arquivos suspeitos, ferramentas de limpeza ou "
        "descriptografadores não verificados.";
    plan->actions[8] =
        "Não pague o resgate sem orientação formal da equipe responsável e "
        "das instâncias internas apropriadas.";
    plan->actions[9] =
        "Peça à equipe responsável que avalie as informações ausentes e "
        "determine os próximos passos; estas orientações não confirmam que "
        "um sistema foi recuperado.";

    plan->action_count = DOCUMENT_RECOVERY_ACTION_COUNT;
    plan->missing_fields = missing;

    return missing == 0
               ? DOCUMENT_RECOVERY_OK
               : DOCUMENT_RECOVERY_INCOMPLETE;
}