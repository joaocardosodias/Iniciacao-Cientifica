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
#include "config.h"

static int build_path(const char *dir, const char *file, char **out)
{
    if (!dir || !file || !out)
        return -1;

    size_t dir_len = strlen(dir);
    int need_slash = (dir_len == 0 || dir[dir_len - 1] != '/');
    if (asprintf(out, "%s%s%s", dir, need_slash ? "/" : "", file) < 0)
        return -1;
    return 0;
}

int write_notice(const char *directory)
{
    char *path = NULL;
    if (build_path(directory, NOTICE_FILENAME, &path) != 0)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t len = strlen(text);
    size_t offset = 0;

    while (offset < len) {
        ssize_t n = write(fd, text + offset, len - offset);
        if (n < 0) {
            close(fd);
            unlink(path);
            free(path);
            return -1;
        }
        offset += (size_t)n;
    }

    close(fd);
    free(path);
    return 0;
}