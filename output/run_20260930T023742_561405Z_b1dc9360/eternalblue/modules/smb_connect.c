#define _GNU_SOURCE
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#endif

static int smb_make_service(int port, char service[6])
{
    char digits[5];
    unsigned int value = (unsigned int)port;
    int count = 0;
    int i;

    do {
        digits[count++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);

    for (i = 0; i < count; ++i)
        service[i] = digits[count - i - 1];
    service[count] = '\0';
    return 0;
}

#ifdef _WIN32
static INIT_ONCE smb_winsock_once = INIT_ONCE_STATIC_INIT;
static int smb_winsock_result = WSASYSNOTREADY;

static BOOL CALLBACK smb_initialize_winsock(PINIT_ONCE once, PVOID parameter,
                                             PVOID *context)
{
    WSADATA data;

    (void)once;
    (void)parameter;
    (void)context;
    smb_winsock_result = WSAStartup(MAKEWORD(2, 2), &data);
    return TRUE;
}
#endif

int smb_connect(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[6];
    int result = -1;

    if (ip == NULL || port < 0 || port > 65535)
        return -1;

#ifdef _WIN32
    if (!InitOnceExecuteOnce(&smb_winsock_once, smb_initialize_winsock,
                             NULL, NULL) ||
        smb_winsock_result != 0)
        return -1;
#endif

    smb_make_service(port, service);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    if (getaddrinfo(ip, service, &hints, &addresses) != 0)
        return -1;

    for (address = addresses; address != NULL; address = address->ai_next) {
#ifdef _WIN32
        SOCKET sock = socket(address->ai_family, address->ai_socktype,
                             address->ai_protocol);
        DWORD timeout = 2000;

        if (sock == INVALID_SOCKET)
            continue;

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&timeout, sizeof(timeout)) == SOCKET_ERROR ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                       (const char *)&timeout, sizeof(timeout)) == SOCKET_ERROR ||
            connect(sock, address->ai_addr, (int)address->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }

        result = (int)sock;
        break;
#else
        int sock = socket(address->ai_family, address->ai_socktype,
                          address->ai_protocol);
        struct timeval timeout;

        if (sock < 0)
            continue;

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) < 0 ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                       &timeout, sizeof(timeout)) < 0 ||
            connect(sock, address->ai_addr,
                    (socklen_t)address->ai_addrlen) < 0) {
            close(sock);
            continue;
        }

        result = sock;
        break;
#endif
    }

    freeaddrinfo(addresses);
    return result;
}