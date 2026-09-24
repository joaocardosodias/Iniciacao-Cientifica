#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *reader = NULL;
    FILE *memory = NULL;
    FILE *installer = NULL;
    char *line = NULL;
    char *contents = NULL;
    size_t line_capacity = 0;
    size_t contents_length = 0;
    ssize_t line_length;
    int found = 0;
    int status;
    int result = -1;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    reader = popen("crontab -l", "r");
    if (reader == NULL)
        goto cleanup;

    memory = open_memstream(&contents, &contents_length);
    if (memory == NULL)
        goto cleanup;

    while ((line_length = getline(&line, &line_capacity, reader)) != -1) {
        if (memchr(line, '\0', (size_t)line_length) != NULL)
            goto cleanup;

        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (fwrite(line, 1, (size_t)line_length, memory) !=
            (size_t)line_length)
            goto cleanup;
    }

    if (ferror(reader))
        goto cleanup;

    status = pclose(reader);
    reader = NULL;
    if (status == -1 || !WIFEXITED(status))
        goto cleanup;

    if (fflush(memory) != 0)
        goto cleanup;

     
    if (WEXITSTATUS(status) != 0 &&
        !(WEXITSTATUS(status) == 1 && contents_length == 0))
        goto cleanup;

    if (found) {
        result = 0;
        goto cleanup;
    }

    if (contents_length != 0 && contents[contents_length - 1] != '\n' &&
        fputc('\n', memory) == EOF)
        goto cleanup;

    if (fprintf(memory, CRON_ENTRY_TEMPLATE, binary_path) < 0)
        goto cleanup;

    if (fflush(memory) != 0)
        goto cleanup;

    if (contents_length == 0 || contents[contents_length - 1] != '\n') {
        if (fputc('\n', memory) == EOF)
            goto cleanup;
    }

    if (fclose(memory) != 0) {
        memory = NULL;
        goto cleanup;
    }
    memory = NULL;

    installer = popen("crontab -", "w");
    if (installer == NULL)
        goto cleanup;

    if (fwrite(contents, 1, contents_length, installer) != contents_length)
        goto cleanup;

    status = pclose(installer);
    installer = NULL;
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto cleanup;

    result = 0;

cleanup:
    if (installer != NULL)
        pclose(installer);
    if (memory != NULL)
        fclose(memory);
    if (reader != NULL)
        pclose(reader);
    free(contents);
    free(line);
    return result;
}