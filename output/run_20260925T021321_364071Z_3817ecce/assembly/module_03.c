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
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

 
int directory_input_and_regular_file_enumeration(const char *dir_path)
{
    DIR *d;
    struct dirent *entry;
    char full_path[PATH_MAX];
    struct stat st;
    int ret = 0;

    if (dir_path == NULL) {
        fprintf(stderr, "Error: directory path is NULL\n");
        return 1;
    }

    d = opendir(dir_path);
    if (d == NULL) {
        fprintf(stderr, "Error opening directory \"%s\": %s\n", dir_path, strerror(errno));
        return 2;
    }

    while ((entry = readdir(d)) != NULL) {
         
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

         
        if (snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name) >= (int)sizeof(full_path)) {
            fprintf(stderr, "Path length overflow for entry \"%s\"\n", entry->d_name);
            ret = 3;
            break;
        }

        if (lstat(full_path, &st) != 0) {
            fprintf(stderr, "lstat failed for \"%s\": %s\n", full_path, strerror(errno));
            ret = 4;
            break;
        }

        if (S_ISREG(st.st_mode)) {
             
            if (printf("%s\n", full_path) < 0) {
                fprintf(stderr, "Failed to write output for \"%s\"\n", full_path);
                ret = 5;
                break;
            }
        }
         
    }

    closedir(d);
    return ret;
}