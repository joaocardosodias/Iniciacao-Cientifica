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
    FILE *reader = NULL;
    FILE *table = NULL;
    FILE *writer = NULL;
    char *contents = NULL;
    char *line = NULL;
    char *entry = NULL;
    size_t contents_len = 0;
    size_t line_cap = 0;
    ssize_t line_len;
    int found = 0;
    int status;
    int result = -1;

    if (binary_path == NULL || *binary_path == '\0')
        return -1;

    reader = popen("crontab -l", "r");
    if (reader == NULL)
        goto cleanup;

    table = open_memstream(&contents, &contents_len);
    if (table == NULL)
        goto cleanup;

    while ((line_len = getline(&line, &line_cap, reader)) != -1) {
        if (strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            found = 1;

        if (fwrite(line, 1, (size_t)line_len, table) != (size_t)line_len)
            goto cleanup;
    }
    if (ferror(reader))
        goto cleanup;

    if (fclose(table) != 0) {
        table = NULL;
        goto cleanup;
    }
    table = NULL;

    status = pclose(reader);
    reader = NULL;
    if (status == -1 || !WIFEXITED(status))
        goto cleanup;
    if (WEXITSTATUS(status) != 0 &&
        !(WEXITSTATUS(status) == 1 && contents_len == 0))
        goto cleanup;

    if (found) {
        result = 0;
        goto cleanup;
    }

    if (asprintf(&entry, CRON_ENTRY_TEMPLATE, binary_path) < 0)
        goto cleanup;

    writer = popen("crontab -", "w");
    if (writer == NULL)
        goto cleanup;

    if (contents_len != 0) {
        if (fwrite(contents, 1, contents_len, writer) != contents_len)
            goto cleanup;
        if (contents[contents_len - 1] != '\n' &&
            fputc('\n', writer) == EOF)
            goto cleanup;
    }

    if (fputs(entry, writer) == EOF)
        goto cleanup;
    if (entry[0] == '\0' || entry[strlen(entry) - 1] != '\n') {
        if (fputc('\n', writer) == EOF)
            goto cleanup;
    }

    status = pclose(writer);
    writer = NULL;
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto cleanup;

    result = 0;

cleanup:
    if (writer != NULL)
        pclose(writer);
    if (table != NULL)
        fclose(table);
    if (reader != NULL)
        pclose(reader);
    free(entry);
    free(line);
    free(contents);
    return result;
}