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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int write_notice(const char *directory)
{
    char *path = NULL;
    FILE *file;
    size_t length = strlen(NOTICE_TEXT);
    int result = 0;

    if (directory == NULL)
        return -1;

    if (asprintf(&path, "%s%s%s", directory,
                 directory[0] != '\0' && directory[strlen(directory) - 1] == '/'
                     ? "" : "/",
                 NOTICE_FILENAME) < 0)
        return -1;

    file = fopen(path, "wb");
    free(path);
    if (file == NULL)
        return -1;

    if (fwrite(NOTICE_TEXT, 1, length, file) != length)
        result = -1;
    if (fclose(file) != 0)
        result = -1;

    return result;
}