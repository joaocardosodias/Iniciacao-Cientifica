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
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    off_t remaining;
    int fd;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1)
        goto fail;
    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        goto fail;
    }
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
        goto fail;

    remaining = st.st_size;
    while (remaining > 0) {
        size_t count = remaining > (off_t)sizeof(zeros)
                     ? sizeof(zeros) : (size_t)remaining;
        ssize_t written = write(fd, zeros, count);

        if (written == -1) {
            if (errno == EINTR)
                continue;
            goto fail;
        }
        if (written == 0) {
            errno = EIO;
            goto fail;
        }
        remaining -= written;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path);

fail:
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return -1;
}