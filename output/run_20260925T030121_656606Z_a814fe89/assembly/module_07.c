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
#include <unistd.h>

int write_notice(const char *directory)
{
    const char contents[] = NOTICE_TEXT;
    int directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;

    int file_fd = openat(directory_fd, NOTICE_FILENAME,
                         O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (file_fd < 0) {
        close(directory_fd);
        return -1;
    }

    size_t offset = 0;
    int result = 0;

    while (offset < sizeof(contents)) {
        ssize_t written = write(file_fd, contents + offset,
                                sizeof(contents) - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            result = -1;
            break;
        }
        if (written == 0) {
            result = -1;
            break;
        }
        offset += (size_t)written;
    }

    if (close(file_fd) < 0)
        result = -1;
    if (close(directory_fd) < 0)
        result = -1;

    return result;
}