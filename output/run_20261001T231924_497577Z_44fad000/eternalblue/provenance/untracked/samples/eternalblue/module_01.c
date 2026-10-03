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
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <stdio.h>

int smb_connect(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *entry;
    struct timeval timeout;
    char service[16];
#ifdef _WIN32
    WSADATA wsa_data;
    SOCKET fd = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
#else
    int fd = -1;
#endif

    if (ip == NULL || port < 0 || port > 65535)
        return -1;

    if (snprintf(service, sizeof(service), "%d", port) < 0)
        return -1;

    hints = (struct addrinfo){0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(ip, service, &hints, &result) != 0)
        return -1;

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    for (entry = result; entry != NULL; entry = entry->ai_next) {
#ifdef _WIN32
        fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (fd == INVALID_SOCKET)
            continue;
        if (connect(fd, entry->ai_addr, (int)entry->ai_addrlen) == SOCKET_ERROR) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
                       (int)sizeof(timeout)) == SOCKET_ERROR ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
                       (int)sizeof(timeout)) == SOCKET_ERROR ||
            (int)fd < 0) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
#else
        fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, entry->ai_addr, entry->ai_addrlen) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
#endif
        break;
    }

    freeaddrinfo(result);
#ifdef _WIN32
    return fd == INVALID_SOCKET ? -1 : (int)fd;
#else
    return fd;
#endif
}