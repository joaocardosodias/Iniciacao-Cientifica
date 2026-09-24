#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *reader = NULL;
    FILE *buffer = NULL;
    FILE *writer = NULL;
    char *contents = NULL;
    char *line = NULL;
    char *entry = NULL;
    size_t contents_len = 0;
    size_t line_capacity = 0;
    ssize_t line_len;
    int found = 0;
    int status;
    int result = -1;

    if (binary_path == NULL)
        return -1;

    reader = popen("crontab -l", "r");
    if (reader == NULL)
        goto done;

    buffer = open_memstream(&contents, &contents_len);
    if (buffer == NULL)
        goto done;

    while ((line_len = getline(&line, &line_capacity, reader)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (fwrite(line, 1, (size_t)line_len, buffer) != (size_t)line_len)
            goto done;
    }

    if (ferror(reader))
        goto done;

    if (fclose(buffer) != 0) {
        buffer = NULL;
        goto done;
    }
    buffer = NULL;

    status = pclose(reader);
    reader = NULL;
    if (status == -1 || !WIFEXITED(status) ||
        (WEXITSTATUS(status) != 0 &&
         !(WEXITSTATUS(status) == 1 && contents_len == 0)))
        goto done;

    if (found) {
        result = 0;
        goto done;
    }

    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0)
        goto done;

    writer = popen("crontab -", "w");
    if (writer == NULL)
        goto done;

    if (contents_len != 0) {
        if (fwrite(contents, 1, contents_len, writer) != contents_len)
            goto done;
        if (contents[contents_len - 1] != '\n' && fputc('\n', writer) == EOF)
            goto done;
    }

    if (fputs(entry, writer) == EOF)
        goto done;

    if (entry[0] == '\0' || entry[strlen(entry) - 1] != '\n') {
        if (fputc('\n', writer) == EOF)
            goto done;
    }

    status = pclose(writer);
    writer = NULL;
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto done;

    result = 0;

done:
    if (writer != NULL)
        pclose(writer);
    if (buffer != NULL)
        fclose(buffer);
    if (reader != NULL)
        pclose(reader);
    free(entry);
    free(line);
    free(contents);
    return result;
}