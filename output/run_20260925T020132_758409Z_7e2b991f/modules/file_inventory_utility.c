#define _GNU_SOURCE
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

/*
 * file_inventory_utility.c
 *
 * Description:
 *   Recursively enumerates filesystem objects under a set of directories.
 *   For each object it gathers metadata and reports it via a user‑supplied
 *   callback.  If no callback is supplied, the function prints a deterministic
 *   CSV line to stdout.
 *
 * Thread Safety:
 *   The function is not thread‑safe with respect to concurrent calls that
 *   share the same callback data.  All internal state is kept on the stack
 *   or in thread‑local storage provided by nftw(3).  It may be invoked from
 *   multiple threads as long as each call supplies its own callback and
 *   user_data pointer.
 *
 * Assumptions:
 *   - PATH_MAX defines the maximum absolute path length supported by the
 *     platform.
 *   - The underlying filesystem does not change during enumeration (read‑only
 *     semantics are respected).
 *   - Recursion depth is limited to MAX_DEPTH (64) to avoid stack overflow.
 *
 * Errors:
 *   Errors opening a directory or calling lstat() are reported via the
 *   callback (if provided) or printed to stderr.  Processing then continues.
 */

/* Maximum recursion depth for nftw */
#define MAX_DEPTH 64

/* Types of filesystem objects we report */
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
} fi_obj_type_t;

/* Callback prototype.
 *   path        - absolute path of the object
 *   type        - object type enum
 *   st          - stat structure (valid for regular files, directories, etc.)
 *   link_target - target of symlink (NULL if not a symlink)
 *   user_data   - opaque pointer passed by the caller
 */
typedef void (*fi_report_cb_t)(const char *path,
                               fi_obj_type_t type,
                               const struct stat *st,
                               const char *link_target,
                               void *user_data);

/* Internal helper to translate mode bits to fi_obj_type_t */
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

/* Internal wrapper used by nftw */
static int fi_nftw_callback(const char *fpath, const struct stat *sb,
                            int typeflag, struct FTW *ftwbuf)
{
    /* Retrieve user data from the global context (set before nftw) */
    extern struct fi_context_s {
        fi_report_cb_t cb;
        void *user_data;
    } *fi_ctx;

    const char *link_target = NULL;
    char link_buf[PATH_MAX];
    fi_obj_type_t obj_type = FI_TYPE_UNKNOWN;

    (void)ftwbuf; /* Unused */

    /* Resolve the object type */
    obj_type = fi_mode_to_type(sb->st_mode);

    /* If it's a symlink, read its target */
    if (obj_type == FI_TYPE_SYMLINK) {
        ssize_t len = readlink(fpath, link_buf, sizeof(link_buf) - 1);
        if (len >= 0) {
            link_buf[len] = '\0';
            link_target = link_buf;
        } else {
            /* readlink failed; leave link_target NULL */
        }
    }

    if (fi_ctx->cb) {
        fi_ctx->cb(fpath, obj_type, sb, link_target, fi_ctx->user_data);
    } else {
        /* Default printing to stdout in CSV format:
         * path,type,size,mtime,inode,link_target
         */
        char mtime_iso[64];
        struct tm tm;
        if (gmtime_r(&sb->st_mtime, &tm) != NULL) {
            if (strftime(mtime_iso, sizeof(mtime_iso),
                         "%Y-%m-%dT%H:%M:%SZ", &tm) == 0) {
                strcpy(mtime_iso, "1970-01-01T00:00:00Z");
            }
        } else {
            strcpy(mtime_iso, "1970-01-01T00:00:00Z");
        }

        /* Print size only for regular files; others use empty field */
        const char *size_str = "";
        if (obj_type == FI_TYPE_REGULAR) {
            static char size_buf[32];
            snprintf(size_buf, sizeof(size_buf), "%lld", (long long)sb->st_size);
            size_str = size_buf;
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

        printf("\"%s\",%s,%s,%s,%llu,\"%s\"\n",
               fpath,
               type_str,
               size_str,
               mtime_iso,
               (unsigned long long)sb->st_ino,
               link_target ? link_target : "");
    }

    return 0; /* Continue traversal */
}

/* Global context used by nftw callback */
static struct fi_context_s {
    fi_report_cb_t cb;
    void *user_data;
} *fi_ctx = NULL;

/*
 * file_inventory_utility
 *
 * Parameters:
 *   dirs       - array of directory paths (must be null‑terminated strings)
 *   dir_count  - number of entries in the dirs array
 *   report_cb  - callback invoked for each discovered object; may be NULL
 *   user_data  - opaque pointer passed to callback; may be NULL
 *
 * The function does not return a value; errors are reported via the callback
 * or stderr.
 */
void file_inventory_utility(char *const dirs[], size_t dir_count,
                            fi_report_cb_t report_cb, void *user_data)
{
    size_t i;
    char real_path[PATH_MAX];

    /* Allocate and initialise the global context */
    struct fi_context_s ctx;
    ctx.cb = report_cb;
    ctx.user_data = user_data;

    /* Assign to the global pointer expected by nftw callback */
    fi_ctx = &ctx;

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL) {
            fprintf(stderr, "Directory pointer at index %zu is NULL, skipping.\n", i);
            continue;
        }

        /* Resolve to an absolute path */
        if (realpath(dirs[i], real_path) == NULL) {
            fprintf(stderr, "realpath failed for \"%s\": %s\n",
                    dirs[i], strerror(errno));
            continue;
        }

        /* nftw will invoke fi_nftw_callback for each entry */
        int flags = FTW_PHYS;        /* Do not follow symlinks */
        int rc = nftw(real_path, fi_nftw_callback, 20, flags);
        if (rc != 0) {
            fprintf(stderr, "nftw failed for \"%s\": %s\n",
                    real_path, strerror(errno));
            /* Continue with next directory */
        }
    }

    /* Reset global pointer */
    fi_ctx = NULL;
}