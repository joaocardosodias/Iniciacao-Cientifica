#define _GNU_SOURCE
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

static int
append_bytes(char **buffer, size_t *length, size_t *capacity,
             const char *data, size_t data_length)
{
    size_t required;
    size_t new_capacity;
    char *new_buffer;

    if (data_length > SIZE_MAX - *length)
        return -1;
    required = *length + data_length;

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
    *length = required;
    return 0;
}

int
schedule_autostart(const char *binary_path)
{
    FILE *reader = NULL;
    FILE *writer = NULL;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    char *contents = NULL;
    size_t contents_length = 0;
    size_t contents_capacity = 0;
    char *entry = NULL;
    int found = 0;
    int read_error = 0;
    int read_status;
    int result = -1;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    reader = popen("crontab -l", "r");
    if (reader == NULL)
        return -1;

    while ((line_length = getline(&line, &line_capacity, reader)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (append_bytes(&contents, &contents_length, &contents_capacity,
                         line, (size_t)line_length) != 0) {
            read_error = 1;
            break;
        }
    }

    if (ferror(reader))
        read_error = 1;

    read_status = pclose(reader);
    reader = NULL;
    free(line);
    line = NULL;

    if (read_error || read_status == -1)
        goto cleanup;

    if (read_status != 0) {
        if (found || contents_length != 0 || !WIFEXITED(read_status) ||
            WEXITSTATUS(read_status) != 1)
            goto cleanup;
    }

    if (found) {
        result = 0;
        goto cleanup;
    }

    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0)
        goto cleanup;

    if (contents_length != 0 &&
        contents[contents_length - 1] != '\n' &&
        append_bytes(&contents, &contents_length, &contents_capacity,
                     "\n", 1) != 0)
        goto cleanup;

    if (append_bytes(&contents, &contents_length, &contents_capacity,
                     entry, strlen(entry)) != 0)
        goto cleanup;

    if (contents_length == 0 ||
        contents[contents_length - 1] != '\n') {
        if (append_bytes(&contents, &contents_length, &contents_capacity,
                         "\n", 1) != 0)
            goto cleanup;
    }

    writer = popen("crontab -", "w");
    if (writer == NULL)
        goto cleanup;

    if (contents_length != 0 &&
        fwrite(contents, 1, contents_length, writer) != contents_length) {
        pclose(writer);
        writer = NULL;
        goto cleanup;
    }

    if (fflush(writer) == EOF) {
        pclose(writer);
        writer = NULL;
        goto cleanup;
    }

    read_status = pclose(writer);
    writer = NULL;
    if (read_status == -1 || !WIFEXITED(read_status) ||
        WEXITSTATUS(read_status) != 0)
        goto cleanup;

    result = 0;

cleanup:
    if (reader != NULL)
        pclose(reader);
    if (writer != NULL)
        pclose(writer);
    free(line);
    free(contents);
    free(entry);
    return result;
}