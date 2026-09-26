#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *input;
    FILE *output;
    char *line = NULL;
    size_t line_capacity = 0;
    char *crontab = NULL;
    size_t crontab_length = 0;
    ssize_t line_length;
    int found = 0;
    int status;
    int result = -1;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    input = popen("crontab -l", "r");
    if (input == NULL)
        return -1;

    while ((line_length = getline(&line, &line_capacity, input)) != -1) {
        size_t length = (size_t)line_length;
        char *updated;

        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        updated = realloc(crontab, crontab_length + length);
        if (updated == NULL)
            goto read_failure;
        crontab = updated;
        memcpy(crontab + crontab_length, line, length);
        crontab_length += length;
    }

    if (ferror(input))
        goto read_failure;

    free(line);
    line = NULL;

    status = pclose(input);
    input = NULL;
    if (status == -1)
        goto cleanup;

    if (!WIFEXITED(status) ||
        (WEXITSTATUS(status) != 0 &&
         !(WEXITSTATUS(status) == 1 && crontab_length == 0)))
        goto cleanup;

    if (found) {
        result = 0;
        goto cleanup;
    }

    {
        int formatted_length = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE,
                                        binary_path);
        char *entry;
        size_t entry_length;
        size_t separator_length;
        size_t newline_length;
        char *updated;

        if (formatted_length < 0)
            goto cleanup;

        entry = malloc((size_t)formatted_length + 1);
        if (entry == NULL)
            goto cleanup;

        if (snprintf(entry, (size_t)formatted_length + 1,
                     CRON_ENTRY_TEMPLATE, binary_path) != formatted_length) {
            free(entry);
            goto cleanup;
        }

        entry_length = (size_t)formatted_length;
        separator_length = crontab_length > 0 &&
                           crontab[crontab_length - 1] != '\n' ? 1 : 0;
        newline_length = entry_length == 0 ||
                         entry[entry_length - 1] != '\n' ? 1 : 0;

        updated = realloc(crontab, crontab_length + separator_length +
                                   entry_length + newline_length);
        if (updated == NULL) {
            free(entry);
            goto cleanup;
        }
        crontab = updated;

        if (separator_length != 0)
            crontab[crontab_length++] = '\n';
        memcpy(crontab + crontab_length, entry, entry_length);
        crontab_length += entry_length;
        if (newline_length != 0)
            crontab[crontab_length++] = '\n';
        free(entry);
    }

    output = popen("crontab -", "w");
    if (output == NULL)
        goto cleanup;

    {
        size_t offset = 0;
        int write_failed = 0;

        while (offset < crontab_length) {
            size_t written = fwrite(crontab + offset, 1,
                                    crontab_length - offset, output);
            if (written == 0) {
                write_failed = 1;
                break;
            }
            offset += written;
        }

        if (ferror(output))
            write_failed = 1;

        status = pclose(output);
        if (!write_failed && status != -1 && WIFEXITED(status) &&
            WEXITSTATUS(status) == 0)
            result = 0;
    }

    goto cleanup;

read_failure:
    free(line);
    pclose(input);

cleanup:
    free(crontab);
    return result;
}