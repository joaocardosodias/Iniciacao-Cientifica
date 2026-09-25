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
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1)
        return -1;

    size_t length = strlen(text);
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, text + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (written == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}