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
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct list_target_files_context {
    char **paths;
    size_t count;
    size_t capacity;
    const char *const *exts;
    size_t ext_count;
    int failed;
};

static char *list_target_files_join(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    size_t separator = dir_len != 0 && dir[dir_len - 1] != '/';

    if (dir_len > (size_t)-1 - separator ||
        dir_len + separator > (size_t)-1 - name_len ||
        dir_len + separator + name_len == (size_t)-1)
        return NULL;

    size_t length = dir_len + separator + name_len;
    char *path = malloc(length + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, dir, dir_len);
    if (separator)
        path[dir_len] = '/';
    memcpy(path + dir_len + separator, name, name_len);
    path[length] = '\0';
    return path;
}

static int list_target_files_matches(const char *name,
                                     const char *const *exts,
                                     size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (exts[i] == NULL)
            continue;

        size_t ext_len = strlen(exts[i]);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static int list_target_files_add(struct list_target_files_context *ctx,
                                 char *path)
{
    if (ctx->count + 1 >= ctx->capacity) {
        size_t new_capacity = ctx->capacity == 0 ? 16 : ctx->capacity * 2;
        if (new_capacity <= ctx->capacity ||
            new_capacity > (size_t)-1 / sizeof(*ctx->paths))
            return -1;

        char **new_paths = realloc(ctx->paths,
                                   new_capacity * sizeof(*ctx->paths));
        if (new_paths == NULL)
            return -1;

        ctx->paths = new_paths;
        ctx->capacity = new_capacity;
    }

    ctx->paths[ctx->count++] = path;
    ctx->paths[ctx->count] = NULL;
    return 0;
}

static void list_target_files_walk(struct list_target_files_context *ctx,
                                   const char *path)
{
    if (ctx->failed)
        return;

    DIR *dir = opendir(path);
    if (dir == NULL)
        return;

    struct dirent *entry;
    while (!ctx->failed && (entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *child = list_target_files_join(path, entry->d_name);
        if (child == NULL) {
            ctx->failed = 1;
            break;
        }

        struct stat st;
        if (lstat(child, &st) != 0) {
            free(child);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            list_target_files_walk(ctx, child);
            free(child);
        } else if (S_ISREG(st.st_mode) &&
                   list_target_files_matches(entry->d_name, ctx->exts,
                                             ctx->ext_count)) {
            if (list_target_files_add(ctx, child) != 0) {
                free(child);
                ctx->failed = 1;
            }
        } else {
            free(child);
        }
    }

    closedir(dir);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    struct list_target_files_context ctx = {
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .exts = exts,
        .ext_count = exts == NULL ? 0 : ext_count,
        .failed = 0
    };

    if (dirs != NULL) {
        for (size_t i = 0; i < dir_count && !ctx.failed; i++) {
            if (dirs[i] == NULL)
                continue;

            const char *dir = dirs[i];
            char *expanded = NULL;
            if (dir[0] == '~') {
                const char *home = getenv("HOME");
                if (home == NULL)
                    continue;

                size_t home_len = strlen(home);
                size_t suffix_len = strlen(dir + 1);
                if (home_len > (size_t)-1 - suffix_len ||
                    home_len + suffix_len == (size_t)-1) {
                    ctx.failed = 1;
                    break;
                }

                expanded = malloc(home_len + suffix_len + 1);
                if (expanded == NULL) {
                    ctx.failed = 1;
                    break;
                }
                memcpy(expanded, home, home_len);
                memcpy(expanded + home_len, dir + 1, suffix_len + 1);
                dir = expanded;
            }

            list_target_files_walk(&ctx, dir);
            free(expanded);
        }
    }

    if (ctx.failed) {
        for (size_t i = 0; i < ctx.count; i++)
            free(ctx.paths[i]);
        free(ctx.paths);
        return 0;
    }

    if (ctx.count == 0) {
        free(ctx.paths);
        return 0;
    }

    *out_paths = ctx.paths;
    return ctx.count;
}