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
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    ssize_t n;
    size_t len;
    const char *p;
    int fd;

    if (!path || !text)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    if (fchmod(fd, 0600) < 0)
        goto fail;

    p = text;
    len = strlen(text);
    while (len > 0) {
        n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto fail;
        }
        if (n == 0) {
            errno = EIO;
            goto fail;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }

    if (close(fd) < 0)
        return -1;
    return 0;

fail:
    {
        int saved = errno;
        close(fd);
        errno = saved;
    }
    return -1;
}