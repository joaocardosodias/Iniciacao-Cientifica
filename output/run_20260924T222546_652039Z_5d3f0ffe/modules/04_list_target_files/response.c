#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

struct path_list {
    char **paths;
    size_t count;
    size_t cap;
};

static void path_list_free(struct path_list *list)
{
    size_t i;

    if (!list->paths)
        return;
    for (i = 0; i < list->count; i++)
        free(list->paths[i]);
    free(list->paths);
    list->paths = NULL;
    list->count = 0;
    list->cap = 0;
}

static int path_list_add(struct path_list *list, const char *path)
{
    char **tmp;
    char *copy;
    size_t ncap;

    if (list->count + 1 >= list->cap) {
        ncap = list->cap ? list->cap * 2 : 16;
        if (ncap < list->count + 2)
            ncap = list->count + 2;
        tmp = realloc(list->paths, ncap * sizeof(*tmp));
        if (!tmp)
            return -1;
        list->paths = tmp;
        list->cap = ncap;
    }
    copy = strdup(path);
    if (!copy)
        return -1;
    list->paths[list->count++] = copy;
    return 0;
}

static int name_has_ext(const char *name, const char *const *exts, size_t ext_count)
{
    size_t nlen, elen, i;
    const char *ext;

    if (!name || !exts)
        return 0;
    nlen = strlen(name);
    for (i = 0; i < ext_count; i++) {
        ext = exts[i];
        if (!ext)
            continue;
        elen = strlen(ext);
        if (elen <= nlen && memcmp(name + (nlen - elen), ext, elen) == 0)
            return 1;
    }
    return 0;
}

static char *expand_leading_tilde(const char *path)
{
    const char *home;
    size_t home_len, rest_len;
    char *out;

    if (!path)
        return NULL;
    if (path[0] != '~' || (path[1] != '\0' && path[1] != '/'))
        return strdup(path);
    home = getenv("HOME");
    if (!home)
        home = "";
    home_len = strlen(home);
    rest_len = strlen(path + 1);
    out = malloc(home_len + rest_len + 1);
    if (!out)
        return NULL;
    memcpy(out, home, home_len);
    memcpy(out + home_len, path + 1, rest_len + 1);
    return out;
}

static int walk_dir(const char *dirpath, const char *const *exts, size_t ext_count,
                    struct path_list *list)
{
    DIR *dir;
    struct dirent *ent;
    struct stat st;
    char *full;
    int rc = 0;

    dir = opendir(dirpath);
    if (!dir)
        return 0;

    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;

        if (asprintf(&full, "%s/%s", dirpath, ent->d_name) < 0) {
            rc = -1;
            break;
        }

        if (lstat(full, &st) != 0) {
            free(full);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            rc = walk_dir(full, exts, ext_count, list);
            free(full);
            if (rc < 0)
                break;
        } else if (S_ISREG(st.st_mode) && name_has_ext(ent->d_name, exts, ext_count)) {
            rc = path_list_add(list, full);
            free(full);
            if (rc < 0)
                break;
        } else {
            free(full);
        }
    }

    closedir(dir);
    return rc;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct path_list list = {0};
    size_t i;
    char *expanded;
    char **tmp;

    if (out_paths)
        *out_paths = NULL;
    if (!out_paths || !dirs || dir_count == 0)
        return 0;

    for (i = 0; i < dir_count; i++) {
        if (!dirs[i])
            continue;
        expanded = expand_leading_tilde(dirs[i]);
        if (!expanded)
            goto fail;
        if (walk_dir(expanded, exts, ext_count, &list) < 0) {
            free(expanded);
            goto fail;
        }
        free(expanded);
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    tmp = realloc(list.paths, (list.count + 1) * sizeof(*tmp));
    if (!tmp)
        goto fail;
    tmp[list.count] = NULL;
    *out_paths = tmp;
    return list.count;

fail:
    path_list_free(&list);
    *out_paths = NULL;
    return 0;
}