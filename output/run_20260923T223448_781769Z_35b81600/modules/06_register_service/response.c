#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stddef.h>

#ifndef AGENT_PATH
#define AGENT_PATH "/usr/local/bin/monitoring-agent"
#endif

/*
 * Verifica se a linha do crontab corresponde exatamente a:
 * @reboot <caminho_do_binario>
 *
 * A linha pode ter espacos/tabs no inicio, espacos/tabs entre @reboot
 * e o caminho, e pode terminar com espacos, \r ou \n.
 */
static int line_is_reboot_entry(const char *line, const char *agent_path) {
    const char *p = line;

    /* Ignora espacos iniciais. */
    while (*p == ' ' || *p == '\t')
        p++;

    if (strncmp(p, "@reboot", 7) != 0)
        return 0;
    p += 7;

    /* Exige um separador apos @reboot. */
    if (*p != ' ' && *p != '\t')
        return 0;

    while (*p == ' ' || *p == '\t')
        p++;

    if (*p == '\0' || *p == '\n' || *p == '\r')
        return 0;

    size_t path_len = strlen(agent_path);

    if (strncmp(p, agent_path, path_len) != 0)
        return 0;

    p += path_len;

    /* Depois do caminho, so pode haver espacos/tabs e final de linha. */
    while (*p == ' ' || *p == '\t')
        p++;

    return (*p == '\0' || *p == '\n' || *p == '\r');
}

/*
 * Registra o agente no crontab do usuario atual.
 *
 * Retorna 0 em caso de sucesso e -1 em caso de falha.
 *
 * A funcao e reentrante: nao usa variaveis globais nem buffers estaticos.
 * A thread-safety global depende da implementacao de popen()/pclose().
 */
int register_service(const char *agent_path) {
    const char *path = (agent_path != NULL) ? agent_path : AGENT_PATH;

    if (path[0] == '\0') {
        fprintf(stderr, "register_service: caminho do agente invalido\n");
        return -1;
    }

    FILE *in = NULL;
    FILE *out = NULL;
    char crontab[4096];
    size_t crontab_len = 0;
    int found = 0;
    int result = -1;

    /* 1. Le o crontab atual. */
    in = popen("crontab -l", "r");
    if (in == NULL) {
        fprintf(stderr, "register_service: falha ao executar 'crontab -l' (popen)\n");
        return -1;
    }

    /*
     * Le o conteudo com buffer fixo e seguro. Se o crontab exceder
     * o limite, abortamos para nao corromper a configuracao.
     */
    while (crontab_len < sizeof(crontab) - 1) {
        size_t room = sizeof(crontab) - 1 - crontab_len;

        if (fgets(crontab + crontab_len, (int)room + 1, in) == NULL)
            break;

        size_t n = strlen(crontab + crontab_len);

        if (n == 0)
            break;

        if (!found && line_is_reboot_entry(crontab + crontab_len, path))
            found = 1;

        crontab_len += n;

        /* Se o buffer encheu, confirma se realmente acabou o arquivo. */
        if (crontab_len >= sizeof(crontab) - 1) {
            int c = fgetc(in);

            if (c != EOF) {
                fprintf(stderr,
                        "register_service: crontab excede o limite de %zu bytes\n",
                        sizeof(crontab) - 1);
                goto done;
            }

            if (ferror(in)) {
                fprintf(stderr, "register_service: erro ao ler crontab (fgetc)\n");
                goto done;
            }

            break;
        }
    }

    if (ferror(in)) {
        fprintf(stderr, "register_service: erro ao ler crontab (fgets)\n");
        goto done;
    }

    int read_status = pclose(in);
    in = NULL;

    /*
     * Se nao ha nenhuma linha, o `crontab -l` pode retornar status != 0
     * por causa de "no crontab for user". Isso representa crontab vazio
     * e deve ser tratado como primeira execucao.
     */
    if (crontab_len > 0 && read_status != 0) {
        fprintf(stderr, "register_service: 'crontab -l' falhou (status=%d)\n", read_status);
        goto done;
    }

    /* 2. Se a entrada @reboot ja existe, nao faz nada. */
    if (found) {
        result = 0;
        goto done;
    }

    /* 3. Adiciona a entrada @reboot via crontab -. */
    out = popen("crontab -", "w");
    if (out == NULL) {
        fprintf(stderr, "register_service: falha ao executar 'crontab -' (popen)\n");
        goto done;
    }

    if (crontab_len > 0) {
        if (fwrite(crontab, 1, crontab_len, out) != crontab_len) {
            fprintf(stderr, "register_service: erro ao escrever crontab existente\n");
            goto done;
        }

        /* Garante que a nova entrada fique em uma linha separada. */
        if (crontab[crontab_len - 1] != '\n') {
            if (fputc('\n', out) == EOF) {
                fprintf(stderr, "register_service: erro ao adicionar separador de linha\n");
                goto done;
            }
        }
    }

    if (fprintf(out, "@reboot %s\n", path) < 0) {
        fprintf(stderr, "register_service: erro ao escrever entrada @reboot\n");
        goto done;
    }

    if (fflush(out) == EOF) {
        fprintf(stderr, "register_service: erro ao dar flush no pipe do crontab\n");
        goto done;
    }

    int write_status = pclose(out);
    out = NULL;

    if (write_status != 0) {
        fprintf(stderr, "register_service: 'crontab -' falhou (status=%d)\n", write_status);
        goto done;
    }

    result = 0;

done:
    if (in != NULL)
        pclose(in);
    if (out != NULL)
        pclose(out);

    return result;
}