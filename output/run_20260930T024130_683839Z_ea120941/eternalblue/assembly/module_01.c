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

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#endif

int smb_connect(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *entry;
    char service[16];
    int status;
    int connected = -1;

    if (ip == NULL || port < 0 || port > 65535)
        return -1;

#ifdef _WIN32
    {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
            return -1;
    }
#endif

    if (snprintf(service, sizeof(service), "%d", port) < 0)
        return -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    status = getaddrinfo(ip, service, &hints, &results);
    if (status != 0)
        return -1;

    for (entry = results; entry != NULL; entry = entry->ai_next) {
#ifdef _WIN32
        SOCKET sock = socket(entry->ai_family, entry->ai_socktype,
                             entry->ai_protocol);
        DWORD timeout_ms = 2000;

        if (sock == INVALID_SOCKET)
            continue;
        if (sock > INT_MAX ||
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                       (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
            connect(sock, entry->ai_addr, (int)entry->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }
        connected = (int)sock;
        break;
#else
        int sock = socket(entry->ai_family, entry->ai_socktype,
                          entry->ai_protocol);
        struct timeval timeout;

        if (sock < 0)
            continue;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout)) < 0 ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       sizeof(timeout)) < 0 ||
            connect(sock, entry->ai_addr, entry->ai_addrlen) < 0) {
            close(sock);
            continue;
        }
        connected = sock;
        break;
#endif
    }

    freeaddrinfo(results);
    return connected;
}