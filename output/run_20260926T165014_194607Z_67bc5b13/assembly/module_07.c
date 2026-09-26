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
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "config.h"

static int write_all(int fd, const void *buf, size_t count)
{
    const char *p = (const char *)buf;
    while (count > 0) {
        ssize_t r = write(fd, p, count);
        if (r < 0)
            return -1;
        p += r;
        count -= r;
    }
    return 0;
}

static char *make_path(const char *dir)
{
    if (!dir)
        return NULL;
    size_t dir_len = strlen(dir);
    int need_slash = (dir_len == 0 || dir[dir_len - 1] != '/');
    size_t fname_len = strlen(NOTICE_FILENAME);
    size_t total = dir_len + (need_slash ? 1 : 0) + fname_len + 1;
    char *path = (char *)malloc(total);
    if (!path)
        return NULL;
    strcpy(path, dir);
    if (need_slash) {
        path[dir_len] = '/';
        path[dir_len + 1] = '\0';
    }
    strcat(path, NOTICE_FILENAME);
    return path;
}

int write_notice(const char *directory)
{
    char *path = make_path(directory);
    if (!path)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    size_t text_len = strlen(NOTICE_TEXT) + 1;  
    int ret = write_all(fd, NOTICE_TEXT, text_len);
    if (close(fd) < 0)
        ret = -1;

    free(path);
    return ret == 0 ? 0 : -1;
}