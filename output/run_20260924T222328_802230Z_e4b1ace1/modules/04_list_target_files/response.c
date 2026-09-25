#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

struct path_list {
    char **items;
    size_t count;
    size_t cap;
};

static int pl_add(struct path_list *pl, char *path) {
    if (pl->count + 1 >= pl->cap) {
        size_t newcap = pl->cap ? pl->cap * 2 : 16;
        char **tmp = realloc(pl->items, newcap * sizeof(char *));
        if (!tmp)
            return -1;
        pl->items = tmp;
        pl->cap = newcap;
    }
    pl->items[pl->count++] = path;
    return 0;
}

static char *expand_home(const char *dir) {
    if (dir[0] == '~' && (dir[1] == '/' || dir[1] == '\0')) {
        const char *home = getenv("HOME");
        if (!home)
            home = "";
        size_t hl = strlen(home);
        size_t rl = strlen(dir + 1);
        char *res = malloc(hl + rl + 1);
        if (!res)
            return NULL;
        memcpy(res, home, hl);
        memcpy(res + hl, dir + 1, rl + 1);
        return res;
    }
    return strdup(dir);
}

static int matches_ext(const char *name, const char *const *exts, size_t ext_count) {
    size_t nl = strlen(name);
    for (size_t i = 0; i < ext_count; i++) {
        size_t el = strlen(exts[i]);
        if (el <= nl && memcmp(name + nl - el, exts[i], el) == 0)
            return 1;
    }
    return 0;
}

static void walk_dir(const char *path, const char *const *exts, size_t ext_count,
                     struct path_list *pl) {
    DIR *d = opendir(path);
    if (!d)
        return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        size_t plen = strlen(path);
        size_t nlen = strlen(ent->d_name);
        int need_slash = (plen > 0 && path[plen - 1] != '/');
        char *full = malloc(plen + (need_slash ? 1 : 0) + nlen + 1);
        if (!full)
            continue;
        memcpy(full, path, plen);
        size_t off = plen;
        if (need_slash)
            full[off++] = '/';
        memcpy(full + off, ent->d_name, nlen + 1);

        struct stat st;
        if (lstat(full, &st) != 0) {
            free(full);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            walk_dir(full, exts, ext_count, pl);
            free(full);
        } else if (S_ISREG(st.st_mode)) {
            if (matches_ext(ent->d_name, exts, ext_count)) {
                if (pl_add(pl, full) != 0)
                    free(full);
            } else {
                free(full);
            }
        } else {
            free(full);
        }
    }

    closedir(d);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                          const char *const *exts, size_t ext_count,
                          char ***out_paths) {
    struct path_list pl = {0};

    if (out_paths)
        *out_paths = NULL;

    for (size_t i = 0; i < dir_count; i++) {
        if (!dirs[i])
            continue;
        char *expanded = expand_home(dirs[i]);
        if (!expanded)
            continue;
        walk_dir(expanded, exts, ext_count, &pl);
        free(expanded);
    }

    if (pl.count == 0) {
        free(pl.items);
        if (out_paths)
            *out_paths = NULL;
        return 0;
    }

    if (pl.count + 1 > pl.cap) {
        char **tmp = realloc(pl.items, (pl.count + 1) * sizeof(char *));
        if (tmp)
            pl.items = tmp;
    }
    pl.items[pl.count] = NULL;

    if (out_paths)
        *out_paths = pl.items;
    else {
        for (size_t i = 0; i < pl.count; i++)
            free(pl.items[i]);
        free(pl.items);
    }

    return pl.count;
}