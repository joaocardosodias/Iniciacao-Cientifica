#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

static int
append_bytes(char **buffer, size_t *length, size_t *capacity,
             const void *bytes, size_t count)
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
        memcpy(*buffer + *length, bytes, count);
    *length += count;
    (*buffer)[*length] = '\0';
    return 0;
}

int
schedule_autostart(const char *binary_path)
{
    FILE *input;
    FILE *output;
    char *buffer = NULL;
    size_t length = 0;
    size_t capacity = 0;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    size_t path_length;
    int found = 0;
    int read_error;
    int input_status;
    int formatted_length;
    char *formatted = NULL;
    int output_error = 0;
    int output_status;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;
    path_length = strlen(binary_path);

    input = popen("crontab -l", "r");
    if (input == NULL)
        return -1;

    while ((line_length = getline(&line, &line_capacity, input)) != -1) {
        if (memmem(line, (size_t)line_length, "@reboot", 7) != NULL &&
            memmem(line, (size_t)line_length, binary_path, path_length) != NULL)
            found = 1;
        if (append_bytes(&buffer, &length, &capacity,
                         line, (size_t)line_length) != 0) {
            free(line);
            free(buffer);
            (void)pclose(input);
            return -1;
        }
    }

    read_error = ferror(input);
    free(line);
    input_status = pclose(input);
    if (read_error || input_status == -1) {
        free(buffer);
        return -1;
    }

    if (!WIFEXITED(input_status) ||
        (WEXITSTATUS(input_status) != 0 &&
         !(WEXITSTATUS(input_status) == 1 && length == 0))) {
        free(buffer);
        return -1;
    }

    if (found) {
        free(buffer);
        return 0;
    }

    formatted_length = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
    if (formatted_length < 0) {
        free(buffer);
        return -1;
    }
    formatted = malloc((size_t)formatted_length + 1);
    if (formatted == NULL) {
        free(buffer);
        return -1;
    }
    if (snprintf(formatted, (size_t)formatted_length + 1,
                 CRON_ENTRY_TEMPLATE, binary_path) != formatted_length) {
        free(formatted);
        free(buffer);
        return -1;
    }

    if (length != 0 && buffer[length - 1] != '\n' &&
        append_bytes(&buffer, &length, &capacity, "\n", 1) != 0) {
        free(formatted);
        free(buffer);
        return -1;
    }
    if (append_bytes(&buffer, &length, &capacity,
                     formatted, (size_t)formatted_length) != 0) {
        free(formatted);
        free(buffer);
        return -1;
    }
    free(formatted);

    if (length == 0 || buffer[length - 1] != '\n') {
        if (append_bytes(&buffer, &length, &capacity, "\n", 1) != 0) {
            free(buffer);
            return -1;
        }
    }

    output = popen("crontab -", "w");
    if (output == NULL) {
        free(buffer);
        return -1;
    }
    if (length != 0 && fwrite(buffer, 1, length, output) != length)
        output_error = 1;
    free(buffer);

    output_status = pclose(output);
    if (output_error || output_status == -1 ||
        !WIFEXITED(output_status) || WEXITSTATUS(output_status) != 0)
        return -1;

    return 0;
}