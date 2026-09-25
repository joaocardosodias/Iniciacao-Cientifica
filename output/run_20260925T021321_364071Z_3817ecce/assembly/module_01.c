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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

 

#ifndef __cplusplus
 
_Static_assert(1, "Compiled as C++ – this utility requires C compilation");
#else
#error "This source must be compiled as C, not C++"
#endif

static int is_socket_fd(int fd)
{
    struct stat st;
    if (fstat(fd, &st) == -1) {
         
        return 0;
    }
    return S_ISSOCK(st.st_mode);
}

 
int implementation_language_and_local_execution(void)
{
#ifdef __linux__
    DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc/self/fd");
    if (!dir) {
         
        return 2;
    }

    while ((entry = readdir(dir)) != NULL) {
         
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

         
        char *endptr;
        long fd_long = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || fd_long < 0)
            continue;  

        int fd = (int)fd_long;
        if (is_socket_fd(fd)) {
            closedir(dir);
            return 1;  
        }
    }

    closedir(dir);
    return 0;  
#else
     
    return 2;
#endif
}