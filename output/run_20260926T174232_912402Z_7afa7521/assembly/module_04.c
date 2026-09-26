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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stddef.h>

struct list_target_files_ctx {
    const char *const *exts;
    size_t ext_count;
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
};

static char *list_target_files_join(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);

    while (base_len > 1 && base[base_len - 1] == '/')
        base_len--;

    int add_slash = !(base_len == 1 && base[0] == '/');
    if (base_len > (size_t)-1 - name_len - (size_t)add_slash - 1)
        return NULL;

    size_t total = base_len + (size_t)add_slash + name_len;
    char *result = malloc(total + 1);
    if (result == NULL)
        return NULL;

    memcpy(result, base, base_len);
    size_t pos = base_len;
    if (add_slash)
        result[pos++] = '/';
    memcpy(result + pos, name, name_len + 1);
    return result;
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

static int list_target_files_append(struct list_target_files_ctx *ctx,
                                    char *path)
{
    if (ctx->count > (size_t)-1 - 2) {
        ctx->failed = 1;
        return -1;
    }

    size_t needed = ctx->count + 2;
    if (needed > ctx->capacity) {
        size_t new_capacity = ctx->capacity == 0 ? 16 : ctx->capacity;
        while (new_capacity < needed) {
            if (new_capacity > (size_t)-1 / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }

        if (new_capacity > (size_t)-1 / sizeof(*ctx->paths)) {
            ctx->failed = 1;
            return -1;
        }

        char **new_paths = realloc(ctx->paths,
                                   new_capacity * sizeof(*ctx->paths));
        if (new_paths == NULL) {
            ctx->failed = 1;
            return -1;
        }

        ctx->paths = new_paths;
        ctx->capacity = new_capacity;
    }

    ctx->paths[ctx->count++] = path;
    ctx->paths[ctx->count] = NULL;
    return 0;
}

static void list_target_files_walk(struct list_target_files_ctx *ctx,
                                   const char *dir_path)
{
    if (ctx->failed)
        return;

    DIR *dir = opendir(dir_path);
    if (dir == NULL)
        return;

    struct dirent *entry;
    while (!ctx->failed && (entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = list_target_files_join(dir_path, entry->d_name);
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
                   list_target_files_matches(entry->d_name, ctx->exts,
                                             ctx->ext_count)) {
            if (list_target_files_append(ctx, path) != 0)
                free(path);
        } else {
            free(path);
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
    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL))
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

        const char *dir_path = dirs[i];
        char *expanded = NULL;

        if (dir_path[0] == '~' &&
            (dir_path[1] == '\0' || dir_path[1] == '/')) {
            const char *home = getenv("HOME");
            if (home == NULL)
                continue;

            size_t home_len = strlen(home);
            size_t tail_len = strlen(dir_path + 1);
            if (home_len > (size_t)-1 - tail_len - 1) {
                ctx.failed = 1;
                break;
            }

            expanded = malloc(home_len + tail_len + 1);
            if (expanded == NULL) {
                ctx.failed = 1;
                break;
            }

            memcpy(expanded, home, home_len);
            memcpy(expanded + home_len, dir_path + 1, tail_len + 1);
            dir_path = expanded;
        }

        list_target_files_walk(&ctx, dir_path);
        free(expanded);
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