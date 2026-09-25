#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <wchar.h>

typedef enum { FI_TYPE_UNKNOWN = 0, FI_TYPE_REGULAR, FI_TYPE_DIRECTORY, FI_TYPE_SYMLINK, FI_TYPE_CHARDEV, FI_TYPE_BLOCKDEV, FI_TYPE_FIFO, FI_TYPE_SOCKET, FI_TYPE_UNKNOWN_DEVICE } fi_obj_type_t;
typedef void (*fi_report_cb_t)(const char *path, fi_obj_type_t type, const struct stat *st, const char *link_target, void *user_data);
typedef enum { FH_SUCCESS = 0, FH_ERR_INVALID_ARG = 1, FH_ERR_OPENDIR = 2, FH_ERR_STAT = 3, FH_ERR_OPENFILE = 4, FH_ERR_READ = 5, FH_ERR_HASH = 6, FH_ERR_JSON = 7 } file_hash_error_t;

extern void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data);
extern int f02(const char *directory_path);

int main(int argc, char *argv[]) {
    // Prepare arguments for f01: directories are argv[1..]
    char **dirs = argv + 1;
    size_t dir_count = (argc > 1) ? (size_t)(argc - 1) : 0;
    // Call f01 with no callback and no user data
    f01(dirs, dir_count, NULL, NULL);
    // Call f02 with argv[0] as directory path
    int ret = f02(argv[0]);
    return ret;
}
