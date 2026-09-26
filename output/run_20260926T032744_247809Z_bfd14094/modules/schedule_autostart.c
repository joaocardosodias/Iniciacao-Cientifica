#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"

static int read_crontab(char **out, int *found, const char *binary_path)
{
    FILE *fp = popen("crontab -l", "r");
    if (!fp)
        return -1;

    char *content = NULL;
    size_t content_len = 0;
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t nread;
    int has_entry = 0;

    while ((nread = getline(&line, &line_cap, fp)) != -1) {
        if (!has_entry) {
            if (strstr(line, "@reboot") && strstr(line, binary_path))
                has_entry = 1;
        }
        char *new_content = realloc(content, content_len + (size_t)nread + 1);
        if (!new_content) {
            free(content);
            free(line);
            pclose(fp);
            return -1;
        }
        content = new_content;
        memcpy(content + content_len, line, (size_t)nread);
        content_len += (size_t)nread;
        content[content_len] = '\0';
    }

    free(line);
    pclose(fp);

    *out = content;
    *found = has_entry;
    return 0;
}

static int write_crontab(const char *content)
{
    FILE *fp = popen("crontab -", "w");
    if (!fp)
        return -1;

    if (fwrite(content, 1, strlen(content), fp) != strlen(content)) {
        pclose(fp);
        return -1;
    }

    if (pclose(fp) == -1)
        return -1;

    return 0;
}

int schedule_autostart(const char *binary_path)
{
    if (!binary_path)
        return -1;

    char *crontab = NULL;
    int has_entry = 0;

    if (read_crontab(&crontab, &has_entry, binary_path) != 0) {
        free(crontab);
        return -1;
    }

    if (!has_entry) {
        char entry_buf[1024];
        int ret = snprintf(entry_buf, sizeof(entry_buf), CRON_ENTRY_TEMPLATE, binary_path);
        if (ret < 0 || (size_t)ret >= sizeof(entry_buf)) {
            free(crontab);
            return -1;
        }
        size_t new_len = (crontab ? strlen(crontab) : 0) + (size_t)ret + 2;
        char *new_content = malloc(new_len);
        if (!new_content) {
            free(crontab);
            return -1;
        }
        if (crontab) {
            strcpy(new_content, crontab);
            strcat(new_content, "\n");
        } else {
            new_content[0] = '\0';
        }
        strcat(new_content, entry_buf);
        strcat(new_content, "\n");

        free(crontab);
        crontab = new_content;
    }

    int result = write_crontab(crontab ? crontab : "");
    free(crontab);
    return result == 0 ? 0 : -1;
}