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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int write_notice(const char *directory)
{
    if (directory == NULL)
        return -1;

    size_t dir_len = strlen(directory);
    size_t name_len = strlen(NOTICE_FILENAME);

    int need_sep = (dir_len > 0 && directory[dir_len - 1] != '/');
    size_t path_len = dir_len + (need_sep ? 1 : 0) + name_len + 1;

    char *path = malloc(path_len);
    if (path == NULL)
        return -1;

    memcpy(path, directory, dir_len);
    size_t pos = dir_len;
    if (need_sep)
        path[pos++] = '/';
    memcpy(path + pos, NOTICE_FILENAME, name_len);
    pos += name_len;
    path[pos] = '\0';

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    free(path);

    const char *text = NOTICE_TEXT;
    size_t total = strlen(text);
    size_t written = 0;

    while (written < total) {
        ssize_t n = write(fd, text + written, total - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }

    if (close(fd) != 0)
        return -1;

    return 0;
}