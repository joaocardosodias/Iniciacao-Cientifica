#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *current = NULL;
    FILE *staging = NULL;
    FILE *installer = NULL;
    char *line = NULL;
    char *entry = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    int entry_length;
    int status;
    int found = 0;
    int saw_output = 0;
    int last_char = '\n';
    int result = -1;
    char buffer[8192];

    if (binary_path == NULL || *binary_path == '\0')
        return -1;

    staging = tmpfile();
    if (staging == NULL)
        goto cleanup;

    current = popen("crontab -l", "r");
    if (current == NULL)
        goto cleanup;

    while ((line_length = getline(&line, &line_capacity, current)) != -1) {
        saw_output = 1;
        last_char = (unsigned char)line[line_length - 1];

        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (fwrite(line, 1, (size_t)line_length, staging) !=
            (size_t)line_length)
            goto cleanup;
    }

    if (ferror(current))
        goto cleanup;

    status = pclose(current);
    current = NULL;
    if (status == -1 ||
        (!WIFEXITED(status)) ||
        (WEXITSTATUS(status) != 0 &&
         !(WEXITSTATUS(status) == 1 && !saw_output)))
        goto cleanup;

    if (found) {
        result = 0;
        goto cleanup;
    }

    entry_length = asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path);
    if (entry_length < 0)
        goto cleanup;

    if (fseek(staging, 0, SEEK_SET) != 0)
        goto cleanup;

    installer = popen("crontab -", "w");
    if (installer == NULL)
        goto cleanup;

    for (;;) {
        size_t count = fread(buffer, 1, sizeof buffer, staging);

        if (count != 0 && fwrite(buffer, 1, count, installer) != count)
            goto cleanup;
        if (count < sizeof buffer) {
            if (ferror(staging))
                goto cleanup;
            break;
        }
    }

    if (saw_output && last_char != '\n' && fputc('\n', installer) == EOF)
        goto cleanup;

    if (entry_length != 0 &&
        fwrite(entry, 1, (size_t)entry_length, installer) !=
        (size_t)entry_length)
        goto cleanup;

    if ((entry_length == 0 || entry[entry_length - 1] != '\n') &&
        fputc('\n', installer) == EOF)
        goto cleanup;

    status = pclose(installer);
    installer = NULL;
    if (status != 0)
        goto cleanup;

    result = 0;

cleanup:
    if (current != NULL)
        pclose(current);
    if (installer != NULL)
        pclose(installer);
    if (staging != NULL && fclose(staging) != 0)
        result = -1;
    free(line);
    free(entry);
    return result;
}