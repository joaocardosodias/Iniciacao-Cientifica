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
    int dir_fd;
    int file_fd;
    const char *text = NOTICE_TEXT;
    size_t length = strlen(text) + 1;
    size_t written = 0;

    if (directory == NULL)
        return -1;

    dir_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd == -1)
        return -1;

    file_fd = openat(dir_fd, NOTICE_FILENAME,
                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (file_fd == -1) {
        close(dir_fd);
        return -1;
    }

    while (written < length) {
        ssize_t n = write(file_fd, text + written, length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(file_fd);
            close(dir_fd);
            return -1;
        }
        if (n == 0) {
            close(file_fd);
            close(dir_fd);
            return -1;
        }
        written += (size_t)n;
    }

    if (close(file_fd) == -1) {
        close(dir_fd);
        return -1;
    }

    if (close(dir_fd) == -1)
        return -1;

    return 0;
}