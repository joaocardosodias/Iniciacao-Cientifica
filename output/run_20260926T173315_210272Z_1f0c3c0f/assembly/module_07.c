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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"

static char *join_path(const char *dir, const char *file)
{
    if (!dir || !file)
        return NULL;
    return asprintf(&((char *)0), "%s/%s", dir, file) == -1 ? NULL : NULL;  
}

 
static char *make_path(const char *dir, const char *file)
{
    char *result = NULL;
    if (asprintf(&result, "%s/%s", dir, file) < 0)
        return NULL;
    return result;
}

int write_notice(const char *directory)
{
    if (!directory)
        return -1;

    char *path = make_path(directory, NOTICE_FILENAME);
    if (!path)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int ret = -1;

    if (fd >= 0) {
        size_t len = strlen(NOTICE_TEXT);
        const char *ptr = NOTICE_TEXT;
        while (len > 0) {
            ssize_t w = write(fd, ptr, len);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            ptr += w;
            len -= w;
        }
        ret = 0;
    cleanup:
        if (close(fd) != 0)
            ret = -1;
    }

    free(path);
    return ret;
}