#define _GNU_SOURCE
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *input;
    char *line = NULL;
    size_t line_capacity = 0;
    char *contents = NULL;
    size_t contents_length = 0;
    size_t contents_capacity = 0;
    size_t path_length;
    ssize_t line_length;
    int found = 0;
    int read_failed = 0;
    int status;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    path_length = strlen(binary_path);
    input = popen("crontab -l", "r");
    if (input == NULL)
        return -1;

    while ((line_length = getline(&line, &line_capacity, input)) != -1) {
        size_t length = (size_t)line_length;

        if (memmem(line, length, "@reboot", sizeof("@reboot") - 1) != NULL &&
            memmem(line, length, binary_path, path_length) != NULL)
            found = 1;

        if (length > SIZE_MAX - contents_length - 1) {
            read_failed = 1;
            break;
        }

        size_t needed = contents_length + length + 1;
        if (needed > contents_capacity) {
            size_t new_capacity = contents_capacity ? contents_capacity : 4096;
            while (new_capacity < needed) {
                if (new_capacity > SIZE_MAX / 2) {
                    new_capacity = needed;
                    break;
                }
                new_capacity *= 2;
            }

            char *new_contents = realloc(contents, new_capacity);
            if (new_contents == NULL) {
                read_failed = 1;
                break;
            }
            contents = new_contents;
            contents_capacity = new_capacity;
        }

        memcpy(contents + contents_length, line, length);
        contents_length += length;
        contents[contents_length] = '\0';
    }

    if (ferror(input))
        read_failed = 1;

    free(line);
    status = pclose(input);
    if (read_failed || status == -1)
        goto error;

    if (!WIFEXITED(status) ||
        (WEXITSTATUS(status) != 0 &&
         !(WEXITSTATUS(status) == 1 && contents_length == 0)))
        goto error;

    if (found) {
        free(contents);
        return 0;
    }

    int formatted_length = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
    if (formatted_length < 0)
        goto error;

    size_t entry_length = (size_t)formatted_length;
    if (entry_length == SIZE_MAX)
        goto error;

    char *entry = malloc(entry_length + 1);
    if (entry == NULL)
        goto error;

    if (snprintf(entry, entry_length + 1, CRON_ENTRY_TEMPLATE, binary_path) !=
        formatted_length) {
        free(entry);
        goto error;
    }

    size_t separator_length =
        contents_length > 0 && contents[contents_length - 1] != '\n' ? 1 : 0;
    size_t terminator_length =
        entry_length > 0 && entry[entry_length - 1] != '\n' ? 1 : 0;

    if (separator_length > SIZE_MAX - contents_length ||
        entry_length > SIZE_MAX - contents_length - separator_length ||
        terminator_length >
            SIZE_MAX - contents_length - separator_length - entry_length) {
        free(entry);
        goto error;
    }

    size_t updated_length =
        contents_length + separator_length + entry_length + terminator_length;
    if (updated_length > contents_capacity) {
        char *updated_contents = realloc(contents, updated_length);
        if (updated_contents == NULL && updated_length != 0) {
            free(entry);
            goto error;
        }
        contents = updated_contents;
        contents_capacity = updated_length;
    }

    size_t offset = contents_length;
    if (separator_length)
        contents[offset++] = '\n';
    memcpy(contents + offset, entry, entry_length);
    offset += entry_length;
    if (terminator_length)
        contents[offset++] = '\n';
    free(entry);

    FILE *output = popen("crontab -", "w");
    if (output == NULL)
        goto error;

    size_t written = 0;
    int write_failed = 0;
    while (written < updated_length) {
        size_t amount = fwrite(contents + written, 1, updated_length - written,
                               output);
        if (amount == 0) {
            write_failed = 1;
            break;
        }
        written += amount;
    }

    if (fflush(output) != 0)
        write_failed = 1;

    status = pclose(output);
    free(contents);

    if (write_failed || status == -1 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return -1;

    return 0;

error:
    free(contents);
    return -1;
}