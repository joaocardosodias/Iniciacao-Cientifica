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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

static char *join_path(const char *dir, const char *file)
{
    size_t dlen = strlen(dir);
    size_t flen = strlen(file);
    size_t need = dlen + (dlen && dir[dlen - 1] != '/' ? 1 : 0) + flen + 1;
    char *p = (char *)malloc(need);
    if (!p)
        return NULL;
    strcpy(p, dir);
    if (dlen && dir[dlen - 1] != '/')
        p[dlen] = '/';
    strcpy(p + dlen + (dlen && dir[dlen - 1] != '/' ? 1 : 0), file);
    return p;
}

int write_notice(const char *directory)
{
    char *path = join_path(directory, NOTICE_FILENAME);
    if (!path)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t total = strlen(text);
    size_t written = 0;
    while (written < total) {
        ssize_t n = write(fd, text + written, total - written);
        if (n <= 0) {
            close(fd);
            free(path);
            return -1;
        }
        written += (size_t)n;
    }

    if (close(fd) < 0) {
        free(path);
        return -1;
    }

    free(path);
    return 0;
}