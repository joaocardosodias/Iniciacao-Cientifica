#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *reader = NULL;
    FILE *table = NULL;
    FILE *writer = NULL;
    char *contents = NULL;
    char *line = NULL;
    char *entry = NULL;
    size_t contents_len = 0;
    size_t line_cap = 0;
    ssize_t line_len;
    int found = 0;
    int status;
    int result = -1;

    if (binary_path == NULL || *binary_path == '\0')
        return -1;

    reader = popen("crontab -l", "r");
    if (reader == NULL)
        goto cleanup;

    table = open_memstream(&contents, &contents_len);
    if (table == NULL)
        goto cleanup;

    while ((line_len = getline(&line, &line_cap, reader)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (fwrite(line, 1, (size_t)line_len, table) != (size_t)line_len)
            goto cleanup;
    }
    if (ferror(reader))
        goto cleanup;

    if (fclose(table) != 0) {
        table = NULL;
        goto cleanup;
    }
    table = NULL;

    status = pclose(reader);
    reader = NULL;
    if (status == -1 || !WIFEXITED(status))
        goto cleanup;
    if (WEXITSTATUS(status) != 0 &&
        !(WEXITSTATUS(status) == 1 && contents_len == 0))
        goto cleanup;

    if (found) {
        result = 0;
        goto cleanup;
    }

    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0)
        goto cleanup;

    writer = popen("crontab -", "w");
    if (writer == NULL)
        goto cleanup;

    if (contents_len != 0) {
        if (fwrite(contents, 1, contents_len, writer) != contents_len)
            goto cleanup;
        if (contents[contents_len - 1] != '\n' &&
            fputc('\n', writer) == EOF)
            goto cleanup;
    }

    if (fputs(entry, writer) == EOF)
        goto cleanup;
    if (entry[0] == '\0' || entry[strlen(entry) - 1] != '\n') {
        if (fputc('\n', writer) == EOF)
            goto cleanup;
    }

    status = pclose(writer);
    writer = NULL;
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto cleanup;

    result = 0;

cleanup:
    if (writer != NULL)
        pclose(writer);
    if (table != NULL)
        fclose(table);
    if (reader != NULL)
        pclose(reader);
    free(entry);
    free(line);
    free(contents);
    return result;
}