#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <libgen.h>

struct file_node {
    char *path;
    struct file_node *next;
};

/* Helper: create a file_node and add it to the list (no duplicates) */
static int
add_path(struct file_node **head, const char *abs_path)
{
    struct file_node *cur;
    for (cur = *head; cur != NULL; cur = cur->next) {
        if (strcmp(cur->path, abs_path) == 0)
            return 0; /* already exists */
    }
    struct file_node *new_node = malloc(sizeof(struct file_node));
    if (!new_node) {
        fprintf(stderr, "add_path: malloc failed\n");
        return -1;
    }
    new_node->path = strdup(abs_path);
    if (!new_node->path) {
        free(new_node);
        fprintf(stderr, "add_path: strdup failed\n");
        return -1;
    }
    new_node->next = *head;
    *head = new_node;
    return 1;
}

/* Check if file extension matches allowed extensions (case‑insensitive) */
static int
is_allowed_ext(const char *path)
{
    static const char *exts[] = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".db", ".backup", ".psd",
        ".zip", ".rar", NULL
    };
    const char *dot = strrchr(path, '.');
    if (!dot)
        return 0;
    size_t len = strlen(dot);
    for (int i = 0; exts[i] != NULL; i++) {
        if (strcasecmp(dot, exts[i]) == 0)
            return 1;
    }
    return 0;
}

/* Recursive scan of a directory (max depth = 50) */
static void
scan_dir(const char *dir_path, struct file_node **head, int depth)
{
    if (depth > 50)
        return;

    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "scan_dir: cannot open directory %s: %s\n",
                dir_path, strerror(errno));
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build full path (dynamic) */
        size_t dirlen = strlen(dir_path);
        size_t namelen = strlen(entry->d_name);
        char *full = malloc(dirlen + 1 + namelen + 1);
        if (!full) {
            fprintf(stderr, "scan_dir: malloc failed\n");
            continue;
        }
        memcpy(full, dir_path, dirlen);
        full[dirlen] = '/';
        memcpy(full + dirlen + 1, entry->d_name, namelen + 1);

        struct stat st;
        if (lstat(full, &st) != 0) {
            fprintf(stderr, "scan_dir: lstat %s failed: %s\n",
                    full, strerror(errno));
            free(full);
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            /* skip symbolic links */
            free(full);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            scan_dir(full, head, depth + 1);
            free(full);
            continue;
        }

        /* Regular file */
        if (!is_allowed_ext(full)) {
            free(full);
            continue;
        }

        /* Resolve to canonical absolute path */
        char *real = realpath(full, NULL);
        if (!real) {
            fprintf(stderr, "scan_dir: realpath %s failed: %s\n",
                    full, strerror(errno));
            free(full);
            continue;
        }
        free(full);

        add_path(head, real);
        free(real);
    }

    closedir(dir);
}

/*
 * scan_directories() – enumerates files from a fixed set of directories,
 * returning a singly linked list of canonical absolute paths for files
 * with allowed extensions. The caller must free the list via free_file_list().
 */
struct file_node *
scan_directories(void)
{
    struct file_node *list = NULL;
    char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "scan_directories: HOME not set\n");
        return NULL;
    }

    /* Base directories to scan */
    static const char *subdirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        NULL
    };

    /* Process user home subdirectories */
    for (int i = 0; subdirs[i] != NULL; i++) {
        size_t hlen = strlen(home);
        size_t slen = strlen(subdirs[i]);
        char *full = malloc(hlen + 1 + slen + 1);
        if (!full) {
            fprintf(stderr, "malloc: failed for base path\n");
            continue;
        }
        memcpy(full, home, hlen);
        full[hlen] = '/';
        memcpy(full + hlen + 1, subdirs[i], slen + 1);

        char *real = realpath(full, NULL);
        free(full);
        if (!real) {
            fprintf(stderr, "scan_directories: %s does not exist or is inaccessible\n",
                    full);
            continue;
        }
        scan_dir(real, &list, 0);
        free(real);
    }

    /* Process /mnt */
    char *mnt = realpath("/mnt", NULL);
    if (mnt) {
        scan_dir(mnt, &list, 0);
        free(mnt);
    } else {
        fprintf(stderr, "scan_directories: /mnt does not exist or is inaccessible\n");
    }

    return list;
}

/* Free the entire file_node list */
void
free_file_list(struct file_node *head)
{
    struct file_node *cur = head;
    while (cur) {
        struct file_node *next = cur->next;
        free(cur->path);
        free(cur);
        cur = next;
    }
}