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
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <limits.h>

static INIT_ONCE smb_wsa_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK smb_wsa_startup(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;

    (void)once;
    (void)parameter;
    (void)context;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

int smb_connect(const char *ip, int port)
{
    struct sockaddr_in address;
#ifdef _WIN32
    SOCKET sock;
    DWORD timeout = 2000;

    if (ip == NULL || port < 1 || port > 65535 ||
        !InitOnceExecuteOnce(&smb_wsa_once, smb_wsa_startup, NULL, NULL))
        return -1;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return -1;

    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1 ||
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
                   (int)sizeof(timeout)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
                   (int)sizeof(timeout)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, (int)sizeof(address)) == SOCKET_ERROR ||
        (unsigned long long)sock > INT_MAX) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
#else
    int sock;
    struct timeval timeout = { 2, 0 };

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1 ||
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ||
        connect(sock, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
#endif
}