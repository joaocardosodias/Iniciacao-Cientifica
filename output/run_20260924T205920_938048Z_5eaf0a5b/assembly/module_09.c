#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *reader = NULL;
    FILE *writer = NULL;
    FILE *saved = NULL;
    char *contents = NULL;
    char *line = NULL;
    char *entry = NULL;
    size_t contents_len = 0;
    size_t line_cap = 0;
    ssize_t line_len;
    int found = 0;
    int read_error = 0;
    int status;
    int entry_len;
    int result = -1;

    if (binary_path == NULL)
        return -1;

    saved = open_memstream(&contents, &contents_len);
    if (saved == NULL)
        goto done;

    reader = popen("crontab -l", "r");
    if (reader == NULL)
        goto done;

    while ((line_len = getline(&line, &line_cap, reader)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (fwrite(line, 1, (size_t)line_len, saved) != (size_t)line_len) {
            read_error = 1;
            break;
        }
    }

    if (ferror(reader))
        read_error = 1;

    status = pclose(reader);
    reader = NULL;

    if (fclose(saved) != 0)
        read_error = 1;
    saved = NULL;

    if (read_error || status == -1 || !WIFEXITED(status) ||
        (WEXITSTATUS(status) != 0 &&
         !(WEXITSTATUS(status) == 1 && contents_len == 0)))
        goto done;

    if (found) {
        result = 0;
        goto done;
    }

    entry_len = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
    if (entry_len < 0)
        goto done;

    entry = malloc((size_t)entry_len + 1);
    if (entry == NULL)
        goto done;

    if (snprintf(entry, (size_t)entry_len + 1,
                 CRON_ENTRY_TEMPLATE, binary_path) != entry_len)
        goto done;

    writer = popen("crontab -", "w");
    if (writer == NULL)
        goto done;

    if ((contents_len != 0 &&
         fwrite(contents, 1, contents_len, writer) != contents_len) ||
        (contents_len != 0 && contents[contents_len - 1] != '\n' &&
         fputc('\n', writer) == EOF) ||
        (entry_len != 0 &&
         fwrite(entry, 1, (size_t)entry_len, writer) != (size_t)entry_len) ||
        (entry_len == 0 || entry[entry_len - 1] != '\n') &&
         fputc('\n', writer) == EOF)
        goto done;

    status = pclose(writer);
    writer = NULL;
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto done;

    result = 0;

done:
    if (reader != NULL)
        pclose(reader);
    if (writer != NULL)
        pclose(writer);
    if (saved != NULL)
        fclose(saved);
    free(entry);
    free(line);
    free(contents);
    return result;
}