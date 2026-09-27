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

struct list_target_files_ctx {
    const char *const *exts;
    size_t ext_count;
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
};

static char *list_target_files_join(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int needs_slash = dir_len != 0 && dir[dir_len - 1] != '/';

    if (dir_len > SIZE_MAX - name_len - (size_t)needs_slash - 1)
        return NULL;

    size_t length = dir_len + (size_t)needs_slash + name_len;
    char *path = malloc(length + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, dir, dir_len);
    if (needs_slash)
        path[dir_len++] = '/';
    memcpy(path + dir_len, name, name_len);
    path[length] = '\0';
    return path;
}

static char *list_target_files_expand_home(const char *path)
{
    if (path[0] != '~')
        return strdup(path);

    const char *home = getenv("HOME");
    if (home == NULL)
        return NULL;

    size_t home_len = strlen(home);
    size_t suffix_len = strlen(path + 1);
    if (home_len > SIZE_MAX - suffix_len - 1)
        return NULL;

    char *expanded = malloc(home_len + suffix_len + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, home_len);
    memcpy(expanded + home_len, path + 1, suffix_len + 1);
    return expanded;
}

static int list_target_files_matches(const struct list_target_files_ctx *ctx,
                                     const char *name)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ctx->ext_count; i++) {
        const char *ext = ctx->exts[i];
        if (ext == NULL)
            continue;

        size_t ext_len = strlen(ext);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, ext, ext_len) == 0)
            return 1;
    }
    return 0;
}

static int list_target_files_add(struct list_target_files_ctx *ctx,
                                 char *path)
{
    if (ctx->count == ctx->capacity) {
        size_t new_capacity = ctx->capacity == 0 ? 16 : ctx->capacity * 2;
        if (new_capacity < ctx->capacity ||
            new_capacity > SIZE_MAX / sizeof(*ctx->paths)) {
            ctx->failed = 1;
            free(path);
            return -1;
        }

        char **new_paths = realloc(ctx->paths,
                                   new_capacity * sizeof(*ctx->paths));
        if (new_paths == NULL) {
            ctx->failed = 1;
            free(path);
            return -1;
        }

        ctx->paths = new_paths;
        ctx->capacity = new_capacity;
    }

    ctx->paths[ctx->count++] = path;
    return 0;
}

static void list_target_files_walk(struct list_target_files_ctx *ctx,
                                   const char *dir)
{
    if (ctx->failed)
        return;

    DIR *stream = opendir(dir);
    if (stream == NULL)
        return;

    struct dirent *entry;
    while (!ctx->failed && (entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = list_target_files_join(dir, entry->d_name);
        if (path == NULL) {
            ctx->failed = 1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            list_target_files_walk(ctx, path);
            free(path);
        } else if (S_ISREG(st.st_mode) &&
                   list_target_files_matches(ctx, entry->d_name)) {
            if (list_target_files_add(ctx, path) != 0)
                break;
        } else {
            free(path);
        }
    }

    closedir(stream);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;
    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL) ||
        ext_count == 0)
        return 0;

    struct list_target_files_ctx ctx = {
        .exts = exts,
        .ext_count = ext_count,
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .failed = 0
    };

    for (size_t i = 0; i < dir_count && !ctx.failed; i++) {
        if (dirs[i] == NULL)
            continue;

        char *root = list_target_files_expand_home(dirs[i]);
        if (root == NULL) {
            ctx.failed = 1;
            break;
        }

        list_target_files_walk(&ctx, root);
        free(root);
    }

    if (ctx.failed || ctx.count == 0) {
        for (size_t i = 0; i < ctx.count; i++)
            free(ctx.paths[i]);
        free(ctx.paths);
        return 0;
    }

    if (ctx.count == SIZE_MAX / sizeof(*ctx.paths)) {
        for (size_t i = 0; i < ctx.count; i++)
            free(ctx.paths[i]);
        free(ctx.paths);
        return 0;
    }

    char **terminated = realloc(ctx.paths,
                                (ctx.count + 1) * sizeof(*ctx.paths));
    if (terminated == NULL) {
        for (size_t i = 0; i < ctx.count; i++)
            free(ctx.paths[i]);
        free(ctx.paths);
        return 0;
    }

    terminated[ctx.count] = NULL;
    *out_paths = terminated;
    return ctx.count;
}