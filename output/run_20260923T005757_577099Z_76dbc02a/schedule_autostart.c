#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

/* schedule_autostart: adds a @reboot entry for the current binary to user's crontab */
int schedule_autostart(const char *argv0) {
    char binary_path[PATH_MAX];
    size_t binlen;

    /* ---------- resolve absolute path ---------- */
    if (argv0 && strchr(argv0, '/')) {
        if (!realpath(argv0, binary_path)) {
            fprintf(stderr, "realpath failed: %s\n", strerror(errno));
            return -1;
        }
    } else {
        ssize_t len = readlink("/proc/self/exe", binary_path, sizeof(binary_path) - 1);
        if (len == -1 || len >= (ssize_t)(sizeof(binary_path) - 1)) {
            fprintf(stderr, "readlink /proc/self/exe failed: %s\n",
                    len == -1 ? strerror(errno) : "buffer too small");
            return -1;
        }
        binary_path[len] = '\0';
    }
    binlen = strlen(binary_path);

    /* ---------- read existing crontab ---------- */
    FILE *fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) {
        fprintf(stderr, "popen(crontab -l) failed: %s\n", strerror(errno));
        return -1;
    }

    /* allocate array for lines (max 1024 entries, should be enough) */
    char **lines = NULL;
    size_t lines_cap = 0;
    size_t lines_cnt = 0;
    char *line = NULL;
    size_t line_len = 0;
    ssize_t read;

    while ((read = getline(&line, &line_len, fp)) != -1) {
        if (lines_cnt >= lines_cap) {
            size_t new_cap = lines_cap ? lines_cap * 2 : 256;
            char **new_lines = realloc(lines, new_cap * sizeof(char*));
            if (!new_lines) {
                fprintf(stderr, "realloc failed\n");
                free(line);
                for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
                free(lines);
                pclose(fp);
                return -1;
            }
            lines = new_lines;
            lines_cap = new_cap;
        }
        lines[lines_cnt] = strdup(line);
        if (!lines[lines_cnt]) {
            fprintf(stderr, "strdup failed\n");
            free(line);
            for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
            free(lines);
            pclose(fp);
            return -1;
        }
        lines_cnt++;
    }
    free(line);
    int pclose_ret = pclose(fp);
    if (pclose_ret == -1 || (pclose_ret != 0 && pclose_ret != 1)) {
        /* pclose may return 1 if crontab -l fails due to no crontab (non-fatal) */
        /* treat only -1 as error; other statuses are informational */
        if (pclose_ret == -1) {
            fprintf(stderr, "pclose failed: %s\n", strerror(errno));
            for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
            free(lines);
            return -1;
        }
    }

    /* ---------- check if entry already exists ---------- */
    int found = 0;
    for (size_t i = 0; i < lines_cnt; i++) {
        const char *l = lines[i];
        size_t llen = strlen(l);
        /* remove trailing newline if present */
        if (llen > 0 && l[llen-1] == '\n') llen--;
        const char *prefix = "@reboot ";
        size_t plen = strlen(prefix);
        if (llen >= plen + binlen && memcmp(l, prefix, plen) == 0 && memcmp(l + plen, binary_path, binlen) == 0) {
            found = 1;
            break;
        }
    }

    if (found) {
        /* already present, cleanup and exit */
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return 0;
    }

    /* ---------- add the entry ---------- */
    fp = popen("crontab -", "w");
    if (!fp) {
        fprintf(stderr, "popen(crontab -) failed: %s\n", strerror(errno));
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    /* write existing lines */
    for (size_t i = 0; i < lines_cnt; i++) {
        size_t llen = strlen(lines[i]);
        /* ensure the line ends with newline, add if missing */
        if (llen > 0 && lines[i][llen-1] == '\n') {
            if (fputs(lines[i], fp) == EOF) {
                fprintf(stderr, "fputs error writing existing line\n");
                pclose(fp);
                for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        } else {
            if (fprintf(fp, "%s\n", lines[i]) < 0) {
                fprintf(stderr, "fprintf error writing existing line\n");
                pclose(fp);
                for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        }
    }

    /* write the new @reboot entry */
    if (fprintf(fp, "@reboot %s\n", binary_path) < 0) {
        fprintf(stderr, "fprintf error writing @reboot entry\n");
        pclose(fp);
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    int pclose_ret2 = pclose(fp);
    if (pclose_ret2 == -1) {
        fprintf(stderr, "pclose failed: %s\n", strerror(errno));
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    /* cleanup */
    for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
    free(lines);
    return 0;
}