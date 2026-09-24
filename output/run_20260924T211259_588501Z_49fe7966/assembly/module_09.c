#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>

int schedule_autostart(const char *binary_path)
{
    FILE *input = NULL;
    char *line = NULL;
    size_t line_capacity = 0;
    char *content = NULL;
    size_t content_length = 0;
    size_t content_capacity = 0;
    int found = 0;
    int read_error = 0;
    int status;

    if (binary_path == NULL)
        return -1;

    input = popen("crontab -l", "r");
    if (input == NULL)
        return -1;

    for (;;) {
        ssize_t nread = getline(&line, &line_capacity, input);

        if (nread < 0)
            break;

        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if ((size_t)nread > SIZE_MAX - content_length - 1) {
            read_error = 1;
            break;
        }

        size_t needed = content_length + (size_t)nread + 1;
        if (needed > content_capacity) {
            size_t new_capacity = content_capacity ? content_capacity : 256;
            while (new_capacity < needed) {
                if (new_capacity > SIZE_MAX / 2) {
                    new_capacity = needed;
                    break;
                }
                new_capacity *= 2;
            }

            char *new_content = realloc(content, new_capacity);
            if (new_content == NULL) {
                read_error = 1;
                break;
            }
            content = new_content;
            content_capacity = new_capacity;
        }

        memcpy(content + content_length, line, (size_t)nread);
        content_length += (size_t)nread;
        content[content_length] = '\0';
    }

    if (ferror(input))
        read_error = 1;

    free(line);
    status = pclose(input);

    if (read_error) {
        free(content);
        return -1;
    }

    if (status == -1 ||
        (!WIFEXITED(status) ||
         (WEXITSTATUS(status) != 0 &&
          !(WEXITSTATUS(status) == 1 && content_length == 0)))) {
        free(content);
        return -1;
    }

    if (found) {
        free(content);
        return 0;
    }

    int entry_length = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
    if (entry_length < 0) {
        free(content);
        return -1;
    }

    char *entry = malloc((size_t)entry_length + 1);
    if (entry == NULL) {
        free(content);
        return -1;
    }

    if (snprintf(entry, (size_t)entry_length + 1, CRON_ENTRY_TEMPLATE,
                 binary_path) != entry_length) {
        free(entry);
        free(content);
        return -1;
    }

    size_t separator_length =
        content_length > 0 && content[content_length - 1] != '\n' ? 1 : 0;
    size_t entry_size = (size_t)entry_length;
    size_t trailing_newline =
        entry_size == 0 || entry[entry_size - 1] != '\n' ? 1 : 0;

    if (separator_length > SIZE_MAX - content_length ||
        entry_size > SIZE_MAX - content_length - separator_length ||
        trailing_newline >
            SIZE_MAX - content_length - separator_length - entry_size) {
        free(entry);
        free(content);
        return -1;
    }

    size_t updated_length =
        content_length + separator_length + entry_size + trailing_newline;
    char *updated = realloc(content, updated_length + 1);
    if (updated == NULL) {
        free(entry);
        free(content);
        return -1;
    }
    content = updated;

    size_t offset = content_length;
    if (separator_length)
        content[offset++] = '\n';
    memcpy(content + offset, entry, entry_size);
    offset += entry_size;
    if (trailing_newline)
        content[offset++] = '\n';
    content[offset] = '\0';
    free(entry);

    FILE *output = popen("crontab -", "w");
    if (output == NULL) {
        free(content);
        return -1;
    }

    int write_error = 0;
    if (updated_length > 0 &&
        fwrite(content, 1, updated_length, output) != updated_length)
        write_error = 1;
    if (fflush(output) != 0)
        write_error = 1;

    status = pclose(output);
    free(content);

    if (write_error || status == -1 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return -1;

    return 0;
}