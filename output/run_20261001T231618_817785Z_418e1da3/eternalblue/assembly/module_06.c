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
#include <windows.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int doublepulsar_check(const char *ip, int port)
{
    const uint8_t *sources[4] = {
        SMB_NEGOTIATE_PKT,
        SMB_SESSION_SETUP_PKT,
        SMB_TREE_CONNECT_PKT,
        DP_PING_PKT
    };
    size_t sizes[4] = {
        sizeof(SMB_NEGOTIATE_PKT),
        sizeof(SMB_SESSION_SETUP_PKT),
        sizeof(SMB_TREE_CONNECT_PKT),
        sizeof(DP_PING_PKT)
    };
    uint8_t *packets[4] = { NULL, NULL, NULL, NULL };
    SOCKET sock = INVALID_SOCKET;
    int result = -1;
    size_t i;

    if (ip == NULL)
        return -1;

    for (i = 0; i < 4; ++i) {
        if (sizes[i] < 2)
            goto cleanup;
        packets[i] = (uint8_t *)malloc(sizes[i]);
        if (packets[i] == NULL)
            goto cleanup;
        memcpy(packets[i], sources[i], sizes[i]);
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        goto cleanup;

    for (i = 0; i < 4; ++i) {
        size_t bytes_to_send = sizes[i] - 1;
        size_t sent = 0;
        uint8_t header[4];
        uint8_t *response = NULL;
        uint32_t body_length;
        size_t frame_length;
        size_t received;

        if (bytes_to_send == 0 || bytes_to_send > (size_t)INT_MAX)
            goto cleanup;

        while (sent < bytes_to_send) {
            int amount = send(sock, (const char *)packets[i] + sent,
                              (int)(bytes_to_send - sent), 0);
            if (amount == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAEINTR)
                    continue;
                goto cleanup;
            }
            if (amount == 0)
                goto cleanup;
            sent += (size_t)amount;
        }

        received = 0;
        while (received < sizeof(header)) {
            int amount = recv(sock, (char *)header + received,
                              (int)(sizeof(header) - received), 0);
            if (amount == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAEINTR)
                    continue;
                goto cleanup;
            }
            if (amount == 0)
                goto cleanup;
            received += (size_t)amount;
        }

        if (header[0] != 0)
            goto cleanup;

        body_length = ((uint32_t)header[1] << 16) |
                      ((uint32_t)header[2] << 8) |
                      (uint32_t)header[3];
        if (body_length > UINT32_C(0x00ffffff))
            goto cleanup;
        frame_length = (size_t)body_length + sizeof(header);
        response = (uint8_t *)malloc(frame_length);
        if (response == NULL)
            goto cleanup;
        memcpy(response, header, sizeof(header));

        received = 0;
        while (received < (size_t)body_length) {
            size_t remaining = (size_t)body_length - received;
            int request = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
            int amount = recv(sock, (char *)response + sizeof(header) + received,
                              request, 0);
            if (amount == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAEINTR)
                    continue;
                free(response);
                goto cleanup;
            }
            if (amount == 0) {
                free(response);
                goto cleanup;
            }
            received += (size_t)amount;
        }

        if (i == 1) {
            if (frame_length < 34) {
                free(response);
                goto cleanup;
            }
            memcpy(packets[2] + 32, response + 32, 2);
        } else if (i == 2) {
            if (frame_length < 30) {
                free(response);
                goto cleanup;
            }
            memcpy(packets[3] + 28, response + 28, 2);
            memcpy(packets[3] + 32, packets[2] + 32, 2);
        } else if (i == 3) {
            if (frame_length <= (size_t)SMB_RESP_MUX_ID_OFFSET) {
                free(response);
                goto cleanup;
            }
            result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;
            free(response);
            break;
        }

        free(response);
    }

cleanup:
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    for (i = 0; i < 4; ++i)
        free(packets[i]);
    return result;
}