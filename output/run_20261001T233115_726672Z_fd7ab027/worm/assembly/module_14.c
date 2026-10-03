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
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int doublepulsar_read_frame(SOCKET sock, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    size_t received = 0;
    size_t payload_length;
    uint8_t *buffer;

    while (received < sizeof(header)) {
        int result = recv(sock, (char *)header + received,
                          (int)(sizeof(header) - received), 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    if (payload_length > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    received = 0;

    while (received < payload_length) {
        size_t remaining = payload_length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)buffer + sizeof(header) + received,
                          chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            free(buffer);
            return -1;
        }
        received += (size_t)result;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + payload_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t *packet = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t packet_length;
    uint8_t user_id[2];
    uint8_t tree_id[2];
    int result = -1;

    if (ip == NULL || port <= 0 || port > 65535)
        return -1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    packet_length = sizeof(SMB_NEGOTIATE_PKT) - 1;
    packet = (uint8_t *)malloc(sizeof(SMB_NEGOTIATE_PKT));
    if (packet == NULL)
        goto cleanup;
    memcpy(packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (doublepulsar_send_all(sock, packet, packet_length) != 0 ||
        doublepulsar_read_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    free(packet);
    packet = NULL;
    free(response);
    response = NULL;

    packet_length = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    packet = (uint8_t *)malloc(sizeof(SMB_SESSION_SETUP_PKT));
    if (packet == NULL)
        goto cleanup;
    memcpy(packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (doublepulsar_send_all(sock, packet, packet_length) != 0 ||
        doublepulsar_read_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 33)
        goto cleanup;
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(packet);
    packet = NULL;
    free(response);
    response = NULL;

    packet_length = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    packet = (uint8_t *)malloc(sizeof(SMB_TREE_CONNECT_PKT));
    if (packet == NULL)
        goto cleanup;
    memcpy(packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    if (packet_length <= 33)
        goto cleanup;
    packet[32] = user_id[0];
    packet[33] = user_id[1];
    if (doublepulsar_send_all(sock, packet, packet_length) != 0 ||
        doublepulsar_read_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 29)
        goto cleanup;
    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(packet);
    packet = NULL;
    free(response);
    response = NULL;

    packet_length = sizeof(DP_PING_PKT) - 1;
    packet = (uint8_t *)malloc(sizeof(DP_PING_PKT));
    if (packet == NULL)
        goto cleanup;
    memcpy(packet, DP_PING_PKT, sizeof(DP_PING_PKT));
    if (packet_length <= 33)
        goto cleanup;
    packet[28] = tree_id[0];
    packet[29] = tree_id[1];
    packet[32] = user_id[0];
    packet[33] = user_id[1];
    if (doublepulsar_send_all(sock, packet, packet_length) != 0 ||
        doublepulsar_read_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= SMB_RESP_MUX_ID_OFFSET)
        goto cleanup;

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(packet);
    free(response);
    closesocket(sock);
    return result;
}