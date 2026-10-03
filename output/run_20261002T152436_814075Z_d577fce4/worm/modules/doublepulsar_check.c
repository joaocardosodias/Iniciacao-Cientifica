#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int doublepulsar_check(const char *ip, int port)
{
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT) - 1];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT) - 1];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT) - 1];
    uint8_t ping_packet[sizeof(DP_PING_PKT) - 1];
    uint8_t *packets[3];
    size_t packet_lengths[3];
    uint8_t user_id[2];
    uint8_t tree_id[2];
    uint8_t header[4];
    uint8_t *response = NULL;
    SOCKET sock;
    size_t response_size;
    size_t sent;
    size_t received;
    uint32_t frame_length;
    int i;
    int result = -1;

    if (ip == NULL)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));

    packets[0] = negotiate_packet;
    packets[1] = session_setup_packet;
    packets[2] = tree_connect_packet;
    packet_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1;
    packet_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    packet_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    for (i = 0; i < 3; ++i) {
        sent = 0;
        if (packet_lengths[i] > INT_MAX)
            goto cleanup;

        while (sent < packet_lengths[i]) {
            int n = send(sock, (const char *)packets[i] + sent,
                         (int)(packet_lengths[i] - sent), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            sent += (size_t)n;
        }

        for (;;) {
            received = 0;
            while (received < sizeof(header)) {
                int n = recv(sock, (char *)header + received,
                             (int)(sizeof(header) - received), 0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }

            frame_length = ((uint32_t)header[1] << 16) |
                           ((uint32_t)header[2] << 8) |
                           (uint32_t)header[3];

            if (header[0] == 0x85 && frame_length == 0)
                continue;
            if (header[0] != 0x00)
                goto cleanup;
            break;
        }

        response_size = (size_t)frame_length + sizeof(header);
        response = (uint8_t *)malloc(response_size);
        if (response == NULL)
            goto cleanup;
        memcpy(response, header, sizeof(header));

        received = 0;
        while (received < (size_t)frame_length) {
            size_t remaining = (size_t)frame_length - received;
            int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int n = recv(sock, (char *)response + sizeof(header) + received,
                         chunk, 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            received += (size_t)n;
        }

        if (i == 1) {
            if (response_size <= 33)
                goto cleanup;
            user_id[0] = response[32];
            user_id[1] = response[33];
            tree_connect_packet[32] = user_id[0];
            tree_connect_packet[33] = user_id[1];
        } else if (i == 2) {
            if (response_size <= 33)
                goto cleanup;
            tree_id[0] = response[28];
            tree_id[1] = response[29];
        }

        free(response);
        response = NULL;
    }

    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];

    sent = 0;
    if (sizeof(DP_PING_PKT) - 1 > INT_MAX)
        goto cleanup;

    while (sent < sizeof(DP_PING_PKT) - 1) {
        int n = send(sock, (const char *)ping_packet + sent,
                     (int)(sizeof(DP_PING_PKT) - 1 - sent), 0);
        if (n == SOCKET_ERROR || n == 0)
            goto cleanup;
        sent += (size_t)n;
    }

    for (;;) {
        received = 0;
        while (received < sizeof(header)) {
            int n = recv(sock, (char *)header + received,
                         (int)(sizeof(header) - received), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            received += (size_t)n;
        }

        frame_length = ((uint32_t)header[1] << 16) |
                       ((uint32_t)header[2] << 8) |
                       (uint32_t)header[3];

        if (header[0] == 0x85 && frame_length == 0)
            continue;
        if (header[0] != 0x00)
            goto cleanup;
        break;
    }

    response_size = (size_t)frame_length + sizeof(header);
    response = (uint8_t *)malloc(response_size);
    if (response == NULL)
        goto cleanup;
    memcpy(response, header, sizeof(header));

    received = 0;
    while (received < (size_t)frame_length) {
        size_t remaining = (size_t)frame_length - received;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        int n = recv(sock, (char *)response + sizeof(header) + received,
                     chunk, 0);
        if (n == SOCKET_ERROR || n == 0)
            goto cleanup;
        received += (size_t)n;
    }

    if (response_size > SMB_RESP_MUX_ID_OFFSET &&
        response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING)
        result = 1;
    else
        result = 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}