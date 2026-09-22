#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef struct FileNode {
    char *full_path;
    struct FileNode *next;
} FileNode;

static int has_valid_extension(const char *path) {
    const char *dot = strrchr(path, '.');
    if (dot == NULL || *(dot + 1) == '\0') return 0;
    const char *ext = dot + 1;
    static const char *exts[] = {"xlsx", "docx", "pdf", "txt", "csv", "jpg", "png", "db", "backup", "psd", "zip", "rar"};
    size_t n = sizeof(exts) / sizeof(exts[0]);
    for (size_t i = 0; i < n; i++) {
        if (strcasecmp(ext, exts[i]) == 0) return 1;
    }
    return 0;
}

static int scan_dir(const char *dir, FileNode **head) {
    DIR *dp = opendir(dir);
    if (dp == NULL) return 0;

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        size_t len = strlen(dir) + strlen(entry->d_name) + 2;
        char *path = malloc(len);
        if (path == NULL) {
            closedir(dp);
            return -1;
        }
        snprintf(path, len, "%s/%s", dir, entry->d_name);

        struct stat st;
        if (lstat(path, &st) == -1) {
            free(path);
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (scan_dir(path, head) == -1) {
                free(path);
                closedir(dp);
                return -1;
            }
            free(path);
        } else if (S_ISREG(st.st_mode)) {
            if (has_valid_extension(path)) {
                int duplicate = 0;
                for (FileNode *cur = *head; cur != NULL; cur = cur->next) {
                    if (strcmp(cur->full_path, path) == 0) {
                        duplicate = 1;
                        break;
                    }
                }

                if (!duplicate) {
                    FileNode *node = malloc(sizeof(FileNode));
                    if (node == NULL) {
                        free(path);
                        closedir(dp);
                        return -1;
                    }
                    node->full_path = path;
                    node->next = *head;
                    *head = node;
                } else {
                    free(path);
                }
            } else {
                free(path);
            }
        } else {
            free(path);
        }
    }

    closedir(dp);
    return 0;
}

static void free_list_internal(FileNode *head) {
    while (head) {
        FileNode *tmp = head;
        head = head->next;
        free(tmp->full_path);
        free(tmp);
    }
}

FileNode* scan_storage(const char *dir1, const char *dir2, const char *dir3,
                       const char *dir4, const char *dir5) {
    FileNode *head = NULL;
    const char *dirs[5] = {dir1, dir2, dir3, dir4, dir5};

    for (int i = 0; i < 5; i++) {
        if (dirs[i] != NULL) {
            if (scan_dir(dirs[i], &head) == -1) {
                free_list_internal(head);
                return NULL;
            }
        }
    }

    if (head == NULL) return NULL;

    FileNode *prev = NULL, *cur = head, *next;
    while (cur) {
        next = cur->next;
        cur->next = prev;
        prev = cur;
        cur = next;
    }

    return prev;
}