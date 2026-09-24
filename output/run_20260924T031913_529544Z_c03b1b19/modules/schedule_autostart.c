#define _GNU_SOURCE
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

static int append_bytes(char **buffer, size_t *length, size_t *capacity,
                        const char *data, size_t data_length)
{
    size_t required;
    size_t new_capacity;
    char *new_buffer;

    if (data_length > SIZE_MAX - *length - 1)
        return -1;
    required = *length + data_length + 1;

    if (required > *capacity) {
        new_capacity = *capacity ? *capacity : 256;
        while (new_capacity < required) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = required;
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

    if (data_length != 0)
        memcpy(*buffer + *length, data, data_length);
    *length += data_length;
    (*buffer)[*length] = '\0';
    return 0;
}

int schedule_autostart(const char *binary_path)
{
    FILE *input = NULL;
    FILE *output = NULL;
    char *contents = NULL;
    char *line = NULL;
    char *entry = NULL;
    size_t contents_length = 0;
    size_t contents_capacity = 0;
    size_t line_capacity = 0;
    size_t binary_length;
    ssize_t line_length;
    int found = 0;
    int status;
    int result = -1;
    int entry_length;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    binary_length = strlen(binary_path);
    input = popen("crontab -l", "r");
    if (input == NULL)
        goto done;

    while ((line_length = getline(&line, &line_capacity, input)) >= 0) {
        if (memmem(line, (size_t)line_length, "@reboot", 7) != NULL &&
            memmem(line, (size_t)line_length, binary_path, binary_length) != NULL)
            found = 1;

        if (append_bytes(&contents, &contents_length, &contents_capacity,
                         line, (size_t)line_length) != 0)
            goto close_input;
    }

    if (ferror(input))
        goto close_input;

    status = pclose(input);
    input = NULL;
    if (status == -1)
        goto done;
    if (!WIFEXITED(status) ||
        (WEXITSTATUS(status) != 0 &&
         !(WEXITSTATUS(status) == 1 && contents_length == 0)))
        goto done;

    if (found) {
        result = 0;
        goto done;
    }

    entry_length = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
    if (entry_length < 0)
        goto done;

    entry = malloc((size_t)entry_length + 1);
    if (entry == NULL)
        goto done;
    if (snprintf(entry, (size_t)entry_length + 1, CRON_ENTRY_TEMPLATE,
                 binary_path) != entry_length)
        goto done;

    if (contents_length != 0 && contents[contents_length - 1] != '\n') {
        if (append_bytes(&contents, &contents_length, &contents_capacity,
                         "\n", 1) != 0)
            goto done;
    }

    if (append_bytes(&contents, &contents_length, &contents_capacity,
                     entry, (size_t)entry_length) != 0)
        goto done;
    if (contents_length == 0 || contents[contents_length - 1] != '\n') {
        if (append_bytes(&contents, &contents_length, &contents_capacity,
                         "\n", 1) != 0)
            goto done;
    }

    output = popen("crontab -", "w");
    if (output == NULL)
        goto done;

    if (contents_length != 0 &&
        fwrite(contents, 1, contents_length, output) != contents_length) {
        pclose(output);
        output = NULL;
        goto done;
    }

    status = pclose(output);
    output = NULL;
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto done;

    result = 0;
    goto done;

close_input:
    pclose(input);
    input = NULL;

done:
    if (input != NULL)
        pclose(input);
    if (output != NULL)
        pclose(output);
    free(line);
    free(entry);
    free(contents);
    return result;
}