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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock;
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping_packet[sizeof(DP_PING_PKT)];
    uint8_t *packets[4];
    size_t packet_lengths[4];
    size_t i;
    int result = -1;

    if (ip == NULL)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));

    if (sizeof(tree_connect_packet) <= 33 ||
        sizeof(ping_packet) <= 33)
        return -1;

    packets[0] = negotiate_packet;
    packets[1] = session_setup_packet;
    packets[2] = tree_connect_packet;
    packets[3] = ping_packet;

    packet_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1;
    packet_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    packet_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    packet_lengths[3] = sizeof(DP_PING_PKT) - 1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    for (i = 0; i < 4; ++i) {
        size_t sent = 0;
        uint8_t header[4];
        size_t received = 0;
        uint32_t payload_length;
        size_t response_length;
        uint8_t *response;
        size_t response_received;

        if (packet_lengths[i] == 0 || packet_lengths[i] > INT_MAX)
            goto cleanup;

        while (sent < packet_lengths[i]) {
            int chunk = (int)(packet_lengths[i] - sent);
            int n = send(sock, (const char *)packets[i] + sent, chunk, 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            sent += (size_t)n;
        }

        while (received < sizeof(header)) {
            int n = recv(sock, (char *)header + received,
                         (int)(sizeof(header) - received), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            received += (size_t)n;
        }

        payload_length = ((uint32_t)header[1] << 16) |
                         ((uint32_t)header[2] << 8) |
                         (uint32_t)header[3];
        response_length = (size_t)payload_length + sizeof(header);
        response = (uint8_t *)malloc(response_length);
        if (response == NULL)
            goto cleanup;

        memcpy(response, header, sizeof(header));
        response_received = sizeof(header);

        while (response_received < response_length) {
            size_t remaining = response_length - response_received;
            int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int n = recv(sock, (char *)response + response_received, chunk, 0);
            if (n == SOCKET_ERROR || n == 0) {
                free(response);
                goto cleanup;
            }
            response_received += (size_t)n;
        }

        if (i == 1) {
            if (response_length <= 33) {
                free(response);
                goto cleanup;
            }
            tree_connect_packet[32] = response[32];
            tree_connect_packet[33] = response[33];
        } else if (i == 2) {
            if (response_length <= 33) {
                free(response);
                goto cleanup;
            }
            ping_packet[28] = response[28];
            ping_packet[29] = response[29];
            ping_packet[32] = response[32];
            ping_packet[33] = response[33];
        } else if (i == 3) {
            if (response_length <= SMB_RESP_MUX_ID_OFFSET) {
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
    closesocket(sock);
    return result;
}