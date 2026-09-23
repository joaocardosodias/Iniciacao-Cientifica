#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * A lista retornada por scan_storage() deve ser liberada pelo chamador:
 *
 * FileNode *n = lista;
 * while (n) {
 *     FileNode *prox = n->next;
 *     free(n->path);
 *     free(n);
 *     n = prox;
 * }
 */

typedef struct FileNode {
    char *path;
    struct FileNode *next;
} FileNode;

static void free_list(FileNode *head) {
    while (head) {
        FileNode *next = head->next;
        free(head->path);
        free(head);
        head = next;
    }
}

static int has_matching_extension(const char *name) {
    static const char *extensions[] = {
        "xlsx", "docx", "pdf", "txt", "csv", "jpg",
        "png", "db", "backup", "psd", "zip", "rar"
    };

    const char *dot = strrchr(name, '.');
    if (!dot || dot == name)
        return 0;

    for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
        if (strcasecmp(dot + 1, extensions[i]) == 0)
            return 1;
    }

    return 0;
}

static int append_file(FileNode **head, FileNode **tail, const char *path) {
    FileNode *node = malloc(sizeof(*node));
    if (!node)
        return 0;

    node->path = strdup(path);
    if (!node->path) {
        free(node);
        return 0;
    }

    node->next = NULL;

    if (*tail)
        (*tail)->next = node;
    else
        *head = node;

    *tail = node;
    return 1;
}

static int scan_dir(const char *dir, FileNode **head, FileNode **tail) {
    DIR *d = opendir(dir);
    if (!d)
        return 1;

    struct dirent *entry;
    int ok = 1;

    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char child[PATH_MAX];
        int len = snprintf(child, sizeof(child), "%s/%s", dir, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(child))
            continue;

        struct stat st;
        if (lstat(child, &st) != 0)
            continue;

        if (S_ISLNK(st.st_mode)) {
            struct stat target;
            if (stat(child, &target) == 0 &&
                S_ISREG(target.st_mode) &&
                has_matching_extension(entry->d_name)) {
                if (!append_file(head, tail, child)) {
                    ok = 0;
                    break;
                }
            }
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!scan_dir(child, head, tail)) {
                ok = 0;
                break;
            }
        } else if (S_ISREG(st.st_mode) && has_matching_extension(entry->d_name)) {
            if (!append_file(head, tail, child)) {
                ok = 0;
                break;
            }
        }
    }

    closedir(d);
    return ok;
}

FileNode *scan_storage(void) {
    FileNode *head = NULL;
    FileNode *tail = NULL;

    const char *home = getenv("HOME");

    if (home && home[0]) {
        static const char *home_subdirs[] = {
            "Documentos_Teste",
            "Documentos",
            "Downloads",
            "Imagens"
        };

        for (size_t i = 0; i < sizeof(home_subdirs) / sizeof(home_subdirs[0]); i++) {
            char base[PATH_MAX];
            int len;
            size_t home_len = strlen(home);

            if (home_len > 0 && home[home_len - 1] == '/')
                len = snprintf(base, sizeof(base), "%s%s", home, home_subdirs[i]);
            else
                len = snprintf(base, sizeof(base), "%s/%s", home, home_subdirs[i]);

            if (len < 0 || (size_t)len >= sizeof(base))
                continue;

            if (!scan_dir(base, &head, &tail)) {
                free_list(head);
                return NULL;
            }
        }
    }

    if (!scan_dir("/mnt", &head, &tail)) {
        free_list(head);
        return NULL;
    }

    return head;
}