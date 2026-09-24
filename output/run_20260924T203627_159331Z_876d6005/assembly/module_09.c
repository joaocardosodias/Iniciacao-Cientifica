#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *input;
    FILE *memory;
    char *content = NULL;
    size_t content_len = 0;
    char *line = NULL;
    size_t line_capacity = 0;
    char *entry = NULL;
    size_t entry_len;
    ssize_t line_len;
    int found = 0;
    int read_error = 0;
    int close_error = 0;
    int status;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    input = popen("crontab -l", "r");
    if (input == NULL)
        return -1;

    memory = open_memstream(&content, &content_len);
    if (memory == NULL) {
        (void)pclose(input);
        return -1;
    }

    while ((line_len = getline(&line, &line_capacity, input)) != -1) {
        if (fwrite(line, 1, (size_t)line_len, memory) != (size_t)line_len) {
            read_error = 1;
            break;
        }
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;
    }

    if (ferror(input))
        read_error = 1;

    free(line);

    if (fclose(memory) != 0)
        read_error = 1;

    status = pclose(input);
    if (status == -1)
        close_error = 1;
    else if (!WIFEXITED(status))
        close_error = 1;
    else if (WEXITSTATUS(status) != 0 && content_len != 0)
        close_error = 1;

    if (read_error || close_error) {
        free(content);
        return -1;
    }

    if (found) {
        free(content);
        return 0;
    }

    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0) {
        free(content);
        return -1;
    }

    entry_len = strlen(entry);

    {
        FILE *output = popen("crontab -", "w");
        int write_error = 0;

        if (output == NULL) {
            free(entry);
            free(content);
            return -1;
        }

        if (content_len != 0 &&
            fwrite(content, 1, content_len, output) != content_len)
            write_error = 1;

        if (content_len != 0 && content[content_len - 1] != '\n' &&
            fputc('\n', output) == EOF)
            write_error = 1;

        if (entry_len != 0 && fwrite(entry, 1, entry_len, output) != entry_len)
            write_error = 1;

        if (entry_len == 0 || entry[entry_len - 1] != '\n') {
            if (fputc('\n', output) == EOF)
                write_error = 1;
        }

        if (fflush(output) != 0)
            write_error = 1;

        status = pclose(output);
        free(entry);
        free(content);

        if (write_error || status == -1 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0)
            return -1;
    }

    return 0;
}