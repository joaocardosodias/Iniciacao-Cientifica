#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>

static int
append_bytes(char **buffer, size_t *length, size_t *capacity,
             const char *data, size_t count)
{
    size_t needed;
    size_t new_capacity;
    char *new_buffer;

    if (count > (size_t)-1 - *length - 1)
        return -1;
    needed = *length + count + 1;

    if (needed > *capacity) {
        new_capacity = *capacity ? *capacity : 256;
        while (new_capacity < needed) {
            if (new_capacity > (size_t)-1 / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }
        new_buffer = realloc(*buffer, new_capacity);
        if (new_buffer == NULL)
            return -1;
        *buffer = new_buffer;
        *capacity = new_capacity;
    }

    if (count != 0)
        memcpy(*buffer + *length, data, count);
    *length += count;
    (*buffer)[*length] = '\0';
    return 0;
}

int
schedule_autostart(const char *binary_path)
{
    FILE *input = NULL;
    FILE *output = NULL;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    char *crontab = NULL;
    size_t crontab_length = 0;
    size_t crontab_capacity = 0;
    char *entry = NULL;
    size_t entry_length;
    int found = 0;
    int read_error = 0;
    int status;
    int result = -1;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    input = popen("crontab -l", "r");
    if (input == NULL)
        goto done;

    while ((line_length = getline(&line, &line_capacity, input)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (append_bytes(&crontab, &crontab_length, &crontab_capacity,
                         line, (size_t)line_length) != 0) {
            read_error = 1;
            break;
        }
    }
    if (ferror(input))
        read_error = 1;

    status = pclose(input);
    input = NULL;
    if (read_error || status == -1)
        goto done;
    if (!WIFEXITED(status))
        goto done;
    if (WEXITSTATUS(status) != 0 &&
        !(WEXITSTATUS(status) == 1 && crontab_length == 0))
        goto done;

    if (found) {
        result = 0;
        goto done;
    }

    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0)
        goto done;
    entry_length = strlen(entry);

    output = popen("crontab -", "w");
    if (output == NULL)
        goto done;

    if (crontab_length != 0 &&
        crontab[crontab_length - 1] != '\n' &&
        fputc('\n', output) == EOF)
        goto close_output;

    if (crontab_length != 0 &&
        fwrite(crontab, 1, crontab_length, output) != crontab_length)
        goto close_output;

    if (crontab_length != 0 &&
        crontab[crontab_length - 1] != '\n') {
        /* The separator was written before the existing crontab above. */
    }

    if (entry_length != 0 &&
        fwrite(entry, 1, entry_length, output) != entry_length)
        goto close_output;
    if (entry_length == 0 || entry[entry_length - 1] != '\n') {
        if (fputc('\n', output) == EOF)
            goto close_output;
    }

close_output:
    status = pclose(output);
    output = NULL;
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto done;

    result = 0;

done:
    if (input != NULL)
        (void)pclose(input);
    if (output != NULL)
        (void)pclose(output);
    free(line);
    free(crontab);
    free(entry);
    return result;
}