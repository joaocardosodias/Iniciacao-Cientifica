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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char *filename = NOTICE_FILENAME;
    const char *text = NOTICE_TEXT;
    int dirfd;
    int fd;
    int saved_errno;
    size_t length;
    size_t written = 0;

    if (directory == NULL || filename == NULL || text == NULL ||
        filename[0] == '\0' || strcmp(filename, ".") == 0 ||
        strcmp(filename, "..") == 0 || strchr(filename, '/') != NULL) {
        errno = EINVAL;
        return -1;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    fd = openat(dirfd, filename,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                0666);
    if (fd == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    length = strlen(text) + 1;
    while (written < length) {
        ssize_t n = write(fd, text + written, length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            close(fd);
            close(dirfd);
            errno = saved_errno;
            return -1;
        }
        if (n == 0) {
            close(fd);
            close(dirfd);
            errno = EIO;
            return -1;
        }
        written += (size_t)n;
    }

    if (close(fd) == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }
    if (close(dirfd) == -1)
        return -1;

    return 0;
}