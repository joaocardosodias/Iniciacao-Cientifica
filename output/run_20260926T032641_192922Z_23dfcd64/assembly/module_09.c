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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "config.h"

int schedule_autostart(const char *binary_path)
{
    FILE *input;
    FILE *memory;
    FILE *output;
    char *contents = NULL;
    size_t contents_length = 0;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    int found = 0;
    int read_error;
    int capture_error = 0;
    int close_error;
    int status;
    char *entry = NULL;
    size_t entry_length;
    int write_error = 0;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    input = popen("crontab -l", "r");
    if (input == NULL)
        return -1;

    memory = open_memstream(&contents, &contents_length);
    if (memory == NULL) {
        pclose(input);
        return -1;
    }

    while ((line_length = getline(&line, &line_capacity, input)) >= 0) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (!capture_error &&
            fwrite(line, 1, (size_t)line_length, memory) !=
                (size_t)line_length)
            capture_error = 1;
    }

    read_error = ferror(input);
    free(line);

    if (fclose(memory) != 0)
        capture_error = 1;

    status = pclose(input);
    if (read_error || capture_error || status == -1)
        goto fail;
    if (!WIFEXITED(status) ||
        (WEXITSTATUS(status) != 0 &&
         !(WEXITSTATUS(status) == 1 && contents_length == 0)))
        goto fail;

    if (found) {
        free(contents);
        return 0;
    }

    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0)
        goto fail;

    entry_length = strlen(entry);
    output = popen("crontab -", "w");
    if (output == NULL)
        goto fail;

    if ((contents_length != 0 &&
         fwrite(contents, 1, contents_length, output) != contents_length) ||
        (contents_length != 0 && contents[contents_length - 1] != '\n' &&
         fputc('\n', output) == EOF) ||
        (entry_length != 0 &&
         fwrite(entry, 1, entry_length, output) != entry_length) ||
        (entry_length == 0 || entry[entry_length - 1] != '\n') &&
         fputc('\n', output) == EOF)
        write_error = 1;

    if (fflush(output) != 0)
        write_error = 1;

    status = pclose(output);
    free(entry);
    free(contents);

    if (write_error || status == -1 || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return -1;

    return 0;

fail:
    free(entry);
    free(contents);
    return -1;
}