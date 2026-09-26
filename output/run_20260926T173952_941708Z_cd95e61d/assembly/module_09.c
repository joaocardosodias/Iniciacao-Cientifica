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
#include <sys/wait.h>

static int append_bytes(char **buffer, size_t *length, size_t *capacity,
                        const void *data, size_t amount)
{
    size_t required;
    size_t new_capacity;
    char *new_buffer;

    if (amount > (size_t)-1 - *length - 1)
        return -1;
    required = *length + amount + 1;

    if (required > *capacity) {
        new_capacity = *capacity ? *capacity : 4096;
        while (new_capacity < required) {
            if (new_capacity > (size_t)-1 / 2) {
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

    if (amount != 0)
        memcpy(*buffer + *length, data, amount);
    *length += amount;
    (*buffer)[*length] = '\0';
    return 0;
}

int schedule_autostart(const char *binary_path)
{
    FILE *read_pipe = NULL;
    FILE *write_pipe = NULL;
    char *crontab = NULL;
    char *line = NULL;
    size_t crontab_length = 0;
    size_t crontab_capacity = 0;
    size_t line_capacity = 0;
    size_t binary_length;
    ssize_t line_length;
    int found = 0;
    int read_status;
    int result = -1;
    int formatted_length;
    char *entry = NULL;
    int write_failed = 0;
    size_t written;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;
    binary_length = strlen(binary_path);

    read_pipe = popen("crontab -l", "r");
    if (read_pipe == NULL)
        goto done;

    while ((line_length = getline(&line, &line_capacity, read_pipe)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (append_bytes(&crontab, &crontab_length, &crontab_capacity,
                         line, (size_t)line_length) != 0)
            goto close_read_pipe;
    }

    if (ferror(read_pipe))
        goto close_read_pipe;

    read_status = pclose(read_pipe);
    read_pipe = NULL;
    if (read_status == -1)
        goto done;
    if ((!WIFEXITED(read_status) || WEXITSTATUS(read_status) != 0) &&
        crontab_length != 0)
        goto done;

    if (found) {
        result = 0;
        goto done;
    }

    formatted_length = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
    if (formatted_length < 0)
        goto done;

    entry = malloc((size_t)formatted_length + 1);
    if (entry == NULL)
        goto done;
    if (snprintf(entry, (size_t)formatted_length + 1,
                 CRON_ENTRY_TEMPLATE, binary_path) != formatted_length)
        goto done;

    if (crontab_length != 0 && crontab[crontab_length - 1] != '\n' &&
        append_bytes(&crontab, &crontab_length, &crontab_capacity,
                     "\n", 1) != 0)
        goto done;

    if (append_bytes(&crontab, &crontab_length, &crontab_capacity,
                     entry, (size_t)formatted_length) != 0)
        goto done;

    if (formatted_length == 0 || entry[formatted_length - 1] != '\n') {
        if (append_bytes(&crontab, &crontab_length, &crontab_capacity,
                         "\n", 1) != 0)
            goto done;
    }

    write_pipe = popen("crontab -", "w");
    if (write_pipe == NULL)
        goto done;

    written = 0;
    while (written < crontab_length) {
        size_t count = fwrite(crontab + written, 1,
                              crontab_length - written, write_pipe);
        if (count == 0) {
            write_failed = 1;
            break;
        }
        written += count;
    }

    read_status = pclose(write_pipe);
    write_pipe = NULL;
    if (!write_failed && read_status != -1 &&
        WIFEXITED(read_status) && WEXITSTATUS(read_status) == 0)
        result = 0;
    goto done;

close_read_pipe:
    read_status = pclose(read_pipe);
    read_pipe = NULL;
    (void)read_status;

done:
    if (read_pipe != NULL)
        (void)pclose(read_pipe);
    if (write_pipe != NULL)
        (void)pclose(write_pipe);
    free(entry);
    free(line);
    free(crontab);
    (void)binary_length;
    return result;
}