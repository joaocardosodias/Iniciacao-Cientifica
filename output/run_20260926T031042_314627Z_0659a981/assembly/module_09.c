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

int schedule_autostart(const char *binary_path)
{
    FILE *input = NULL;
    FILE *memory = NULL;
    FILE *output = NULL;
    char *content = NULL;
    char *line = NULL;
    char *entry = NULL;
    size_t content_length = 0;
    size_t line_capacity = 0;
    size_t entry_length;
    ssize_t line_length;
    int found = 0;
    int read_error = 0;
    int status;
    int result = -1;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    input = popen("crontab -l", "r");
    if (input == NULL)
        goto done;

    memory = open_memstream(&content, &content_length);
    if (memory == NULL)
        goto done;

    while ((line_length = getline(&line, &line_capacity, input)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (fwrite(line, 1, (size_t)line_length, memory) !=
            (size_t)line_length) {
            read_error = 1;
            break;
        }
    }

    if (ferror(input))
        read_error = 1;

    status = pclose(input);
    input = NULL;

    if (fclose(memory) != 0)
        read_error = 1;
    memory = NULL;

    if (read_error || status == -1)
        goto done;

    if (!WIFEXITED(status))
        goto done;

    if (WEXITSTATUS(status) != 0 &&
        !(WEXITSTATUS(status) == 1 && content_length == 0))
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

    if (content_length != 0) {
        if (fwrite(content, 1, content_length, output) != content_length)
            read_error = 1;
        if (!read_error && content[content_length - 1] != '\n' &&
            fputc('\n', output) == EOF)
            read_error = 1;
    }

    if (!read_error &&
        fwrite(entry, 1, entry_length, output) != entry_length)
        read_error = 1;

    if (!read_error &&
        (entry_length == 0 || entry[entry_length - 1] != '\n') &&
        fputc('\n', output) == EOF)
        read_error = 1;

    status = pclose(output);
    output = NULL;

    if (read_error || status == -1 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        goto done;

    result = 0;

done:
    if (input != NULL)
        (void)pclose(input);
    if (memory != NULL)
        (void)fclose(memory);
    if (output != NULL)
        (void)pclose(output);
    free(line);
    free(content);
    free(entry);
    return result;
}