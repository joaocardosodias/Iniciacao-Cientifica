#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/wait.h> // for pclose status macros

/**
 * update_crontab - Ensure the current binary is registered under @reboot
 *                  in the user's crontab.
 *
 * @argc: Argument count from main (unused).
 * @argv: Argument vector from main (argv[0] used to locate binary).
 * Return: 0 on success (entry already present or added), -1 on error.
 */
int update_crontab(int argc, char *argv[]) {
    (void)argc;  /* not used */

    /* ---------- Step 1: Read current crontab ---------- */
    FILE *fp = popen("crontab -l", "r");
    if (fp == NULL) {
        perror("popen(crontab -l)");
        return -1;
    }

    char **lines = NULL;          /* array of lines (each including newline) */
    size_t count = 0;
    size_t capacity = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    /* Read all lines into dynamic array */
    while ((nread = getline(&line, &len, fp)) != -1) {
        if (count >= capacity) {
            size_t new_cap = capacity == 0 ? 16 : capacity * 2;
            char **new_lines = realloc(lines, new_cap * sizeof(char *));
            if (new_lines == NULL) {
                perror("realloc(lines)");
                free(line);
                for (size_t i = 0; i < count; i++) free(lines[i]);
                free(lines);
                pclose(fp);
                return -1;
            }
            lines = new_lines;
            capacity = new_cap;
        }
        lines[count] = strdup(line);
        if (lines[count] == NULL) {
            perror("strdup");
            free(line);
            for (size_t i = 0; i < count; i++) free(lines[i]);
            free(lines);
            pclose(fp);
            return -1;
        }
        count++;
    }
    free(line);  /* getline buffer no longer needed */

    /* Close read pipe (ignore exit status as per spec for reading) */
    pclose(fp);

    /* ---------- Step 2: Determine absolute binary path ---------- */
    char resolved_path[PATH_MAX];
    char *binary_path = NULL;
    if (realpath(argv[0], resolved_path) != NULL) {
        binary_path = strdup(resolved_path);
    } else {
        /* Fallback: use argv[0] as-is */
        binary_path = strdup(argv[0]);
    }
    if (binary_path == NULL) {
        perror("strdup binary_path");
        for (size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    /* ---------- Step 3: Build expected line and check existence ---------- */
    /* exact line format: "@reboot <binary_path>\n" */
    char *expected_line = NULL;
    int ret = asprintf(&expected_line, "@reboot %s\n", binary_path);
    if (ret < 0 || expected_line == NULL) {
        perror("asprintf");
        free(binary_path);
        for (size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(lines[i], expected_line) == 0) {
            found = 1;
            break;
        }
    }

    /* ---------- Step 4: If not found, write new crontab ---------- */
    if (!found) {
        FILE *wfp = popen("crontab -", "w");
        if (wfp == NULL) {
            perror("popen(crontab -)");
            free(expected_line);
            free(binary_path);
            for (size_t i = 0; i < count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        /* Write existing lines */
        for (size_t i = 0; i < count; i++) {
            if (fputs(lines[i], wfp) == EOF) {
                perror("fputs existing line");
                pclose(wfp);
                free(expected_line);
                free(binary_path);
                for (size_t i = 0; i < count; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        }

        /* Append the @reboot entry */
        if (fputs(expected_line, wfp) == EOF) {
            perror("fputs reboot entry");
            pclose(wfp);
            free(expected_line);
            free(binary_path);
            for (size_t i = 0; i < count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        /* Close write pipe and check exit status */
        int status = pclose(wfp);
        if (status == -1) {
            perror("pclose(crontab -)");
            free(expected_line);
            free(binary_path);
            for (size_t i = 0; i < count; i++) free(lines[i]);
            free(lines);
            return -1;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "crontab command failed with exit code %d\n",
                    WEXITSTATUS(status));
            free(expected_line);
            free(binary_path);
            for (size_t i = 0; i < count; i++) free(lines[i]);
            free(lines);
            return -1;
        }
    }

    /* ---------- Cleanup ---------- */
    for (size_t i = 0; i < count; i++) free(lines[i]);
    free(lines);
    free(binary_path);
    free(expected_line);

    return 0;
}