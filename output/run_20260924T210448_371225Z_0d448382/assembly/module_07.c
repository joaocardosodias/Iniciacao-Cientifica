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
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    int dirfd;
    int fd;
    const char *text = NOTICE_TEXT;
    size_t remaining;
    int saved_errno;

    if (directory == NULL) {
        errno = EINVAL;
        return -1;
    }

    dirfd = open(directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    fd = openat(dirfd, NOTICE_FILENAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    remaining = strlen(text);
    while (remaining != 0) {
        ssize_t written = write(fd, text, remaining);

        if (written == -1) {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            close(fd);
            close(dirfd);
            errno = saved_errno;
            return -1;
        }
        if (written == 0) {
            close(fd);
            close(dirfd);
            errno = EIO;
            return -1;
        }

        text += written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    return close(dirfd) == 0 ? 0 : -1;
}