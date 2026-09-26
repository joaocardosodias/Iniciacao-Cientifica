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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    char *path = NULL;
    int fd;
    int result = -1;
    size_t length = strlen(NOTICE_TEXT);
    size_t offset = 0;

    if (directory == NULL)
        return -1;

    if (asprintf(&path, "%s/%s", directory, NOTICE_FILENAME) < 0)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    free(path);
    if (fd < 0)
        return -1;

    while (offset < length) {
        ssize_t written = write(fd, NOTICE_TEXT + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            goto out;
        }
        if (written == 0) {
            errno = EIO;
            goto out;
        }
        offset += (size_t)written;
    }

    result = 0;

out:
    if (close(fd) < 0)
        result = -1;
    return result;
}