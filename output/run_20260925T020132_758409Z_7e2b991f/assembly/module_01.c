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
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ftw.h>
#include <errno.h>
#include <time.h>

 

 
#define MAX_DEPTH 64

 
typedef enum {
    FI_TYPE_UNKNOWN = 0,
    FI_TYPE_REGULAR,
    FI_TYPE_DIRECTORY,
    FI_TYPE_SYMLINK,
    FI_TYPE_CHARDEV,
    FI_TYPE_BLOCKDEV,
    FI_TYPE_FIFO,
    FI_TYPE_SOCKET,
    FI_TYPE_UNKNOWN_DEVICE
}

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
} fi_obj_type_t;

 
typedef void (*fi_report_cb_t)(const char *path,
                               fi_obj_type_t type,
                               const struct stat *st,
                               const char *link_target,
                               void *user_data);

 
static fi_obj_type_t fi_mode_to_type(mode_t mode)
{
    if (S_ISREG(mode))   return FI_TYPE_REGULAR;
    if (S_ISDIR(mode))   return FI_TYPE_DIRECTORY;
    if (S_ISLNK(mode))   return FI_TYPE_SYMLINK;
    if (S_ISCHR(mode))   return FI_TYPE_CHARDEV;
    if (S_ISBLK(mode))   return FI_TYPE_BLOCKDEV;
    if (S_ISFIFO(mode))  return FI_TYPE_FIFO;
    if (S_ISSOCK(mode))  return FI_TYPE_SOCKET;
    return FI_TYPE_UNKNOWN_DEVICE;
}

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

 
static int fi_nftw_callback(const char *fpath, const struct stat *sb,
                            int typeflag, struct FTW *ftwbuf)
{
     
    extern struct fi_context_s {
        fi_report_cb_t cb;
        void *user_data;
    }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
} *fi_ctx;

    const char *link_target = NULL;
    char link_buf[PATH_MAX];
    fi_obj_type_t obj_type = FI_TYPE_UNKNOWN;

    (void)ftwbuf;  

     
    obj_type = fi_mode_to_type(sb->st_mode);

     
    if (obj_type == FI_TYPE_SYMLINK) {
        ssize_t len = readlink(fpath, link_buf, sizeof(link_buf) - 1);
        if (len >= 0) {
            link_buf[len] = '\0';
            link_target = link_buf;
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
} else {
             
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}
    }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

    if (fi_ctx->cb) {
        fi_ctx->cb(fpath, obj_type, sb, link_target, fi_ctx->user_data);
    }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
} else {
         
        char mtime_iso[64];
        struct tm tm;
        if (gmtime_r(&sb->st_mtime, &tm) != NULL) {
            if (strftime(mtime_iso, sizeof(mtime_iso),
                         "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
                strcpy(mtime_iso, "1970-01-01T00:00:00Z");
            }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
} else {
            strcpy(mtime_iso, "1970-01-01T00:00:00Z");
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

         
        const char *size_str = "";
        if (obj_type == FI_TYPE_REGULAR) {
            static char size_buf[32];
            snprintf(size_buf, sizeof(size_buf), "%lld", (long long)sb->st_size);
            size_str = size_buf;
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

        const char *type_str;
        switch (obj_type) {
            case FI_TYPE_REGULAR: type_str = "regular"; break;
            case FI_TYPE_DIRECTORY: type_str = "directory"; break;
            case FI_TYPE_SYMLINK: type_str = "symlink"; break;
            case FI_TYPE_CHARDEV: type_str = "chardev"; break;
            case FI_TYPE_BLOCKDEV: type_str = "blockdev"; break;
            case FI_TYPE_FIFO: type_str = "fifo"; break;
            case FI_TYPE_SOCKET: type_str = "socket"; break;
            default: type_str = "unknown";
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

        printf("\"%s\",%s,%s,%s,%llu,\"%s\"\n",
               fpath,
               type_str,
               size_str,
               mtime_iso,
               (unsigned long long)sb->st_ino,
               link_target ? link_target : "");
    }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

    return 0;  
}

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

 
static struct fi_context_s {
    fi_report_cb_t cb;
    void *user_data;
}

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
};
static struct fi_context_s *fi_ctx = NULL;

 
void file_inventory_utility(char *const dirs[], size_t dir_count,
                            fi_report_cb_t report_cb, void *user_data)
{
    size_t i;
    char real_path[PATH_MAX];

     
    struct fi_context_s ctx;
    ctx.cb = report_cb;
    ctx.user_data = user_data;

     
    fi_ctx = &ctx;

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL) {
            fprintf(stderr, "Directory pointer at index %zu is NULL, skipping.\n", i);
            continue;
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

         
        if (realpath(dirs[i], real_path) == NULL) {
            fprintf(stderr, "realpath failed for \"%s\": %s\n",
                    dirs[i], strerror(errno));
            continue;
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

         
        int flags = FTW_PHYS;         
        int rc = nftw(real_path, fi_nftw_callback, 20, flags);
        if (rc != 0) {
            fprintf(stderr, "nftw failed for \"%s\": %s\n",
                    real_path, strerror(errno));
             
        }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}
    }

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}

     
    fi_ctx = NULL;
}

void f01(char *const dirs[], size_t dir_count, fi_report_cb_t report_cb, void *user_data) {
    file_inventory_utility(dirs, dir_count, report_cb, user_data);
}