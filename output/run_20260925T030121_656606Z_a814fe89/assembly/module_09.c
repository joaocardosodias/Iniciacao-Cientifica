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

static int append_data(char **buffer, size_t *length, const char *data,
                       size_t data_length)
{
    char *updated = realloc(*buffer, *length + data_length + 1);
    if (updated == NULL)
        return -1;

    memcpy(updated + *length, data, data_length);
    *length += data_length;
    updated[*length] = '\0';
    *buffer = updated;
    return 0;
}

int schedule_autostart(const char *binary_path)
{
    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    FILE *input = popen("crontab -l", "r");
    if (input == NULL)
        return -1;

    char *buffer = NULL;
    size_t length = 0;
    char *line = NULL;
    size_t line_capacity = 0;
    int found = 0;
    ssize_t line_length;

    while ((line_length = getline(&line, &line_capacity, input)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (append_data(&buffer, &length, line, (size_t)line_length) != 0) {
            free(line);
            free(buffer);
            (void)pclose(input);
            return -1;
        }
    }

    int read_error = ferror(input);
    free(line);
    int read_status = pclose(input);
    if (read_error || read_status == -1) {
        free(buffer);
        return -1;
    }

    if (read_status != 0 && length != 0) {
        free(buffer);
        return -1;
    }

    if (found) {
        free(buffer);
        return 0;
    }

    char *entry = NULL;
    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0) {
        free(buffer);
        return -1;
    }

    size_t entry_length = strlen(entry);
    if (length != 0 && buffer[length - 1] != '\n' &&
        append_data(&buffer, &length, "\n", 1) != 0) {
        free(entry);
        free(buffer);
        return -1;
    }

    if (append_data(&buffer, &length, entry, entry_length) != 0) {
        free(entry);
        free(buffer);
        return -1;
    }
    free(entry);

    if (length == 0 || buffer[length - 1] != '\n') {
        if (append_data(&buffer, &length, "\n", 1) != 0) {
            free(buffer);
            return -1;
        }
    }

    FILE *output = popen("crontab -", "w");
    if (output == NULL) {
        free(buffer);
        return -1;
    }

    int write_error = length != 0 &&
                      fwrite(buffer, 1, length, output) != length;
    int write_status = pclose(output);
    free(buffer);

    if (write_error || write_status == -1 ||
        !WIFEXITED(write_status) || WEXITSTATUS(write_status) != 0)
        return -1;

    return 0;
}