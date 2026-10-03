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
#include <limits.h>
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
        int result = send(sock, (const char *)(data + sent), chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)(data + received), chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int doublepulsar_receive_frame(SOCKET sock, uint8_t **frame_out,
                                      size_t *frame_length_out)
{
    uint8_t header[4];
    uint8_t *frame;
    size_t body_length;

    if (frame_out == NULL || frame_length_out == NULL) {
        return -1;
    }

    *frame_out = NULL;
    *frame_length_out = 0;

    for (;;) {
        if (doublepulsar_recv_exact(sock, header, sizeof(header)) != 0) {
            return -1;
        }

        body_length = ((size_t)header[1] << 16) |
                      ((size_t)header[2] << 8) |
                      (size_t)header[3];

        if (header[0] == 0x85 && body_length == 0) {
            continue;
        }

        if (body_length > SIZE_MAX - sizeof(header)) {
            return -1;
        }

        frame = (uint8_t *)malloc(sizeof(header) + body_length);
        if (frame == NULL) {
            return -1;
        }

        memcpy(frame, header, sizeof(header));
        if (body_length != 0 &&
            doublepulsar_recv_exact(sock, frame + sizeof(header), body_length) != 0) {
            free(frame);
            return -1;
        }

        *frame_out = frame;
        *frame_length_out = sizeof(header) + body_length;
        return 0;
    }
}

static int doublepulsar_exchange(SOCKET sock, const uint8_t *packet,
                                 size_t packet_length, uint8_t **response,
                                 size_t *response_length)
{
    if (packet == NULL || packet_length == 0 ||
        doublepulsar_send_all(sock, packet, packet_length) != 0) {
        return -1;
    }

    return doublepulsar_receive_frame(sock, response, response_length);
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t *negotiate = NULL;
    uint8_t *session_setup = NULL;
    uint8_t *tree_connect = NULL;
    uint8_t *ping = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t negotiate_length = sizeof(SMB_NEGOTIATE_PKT) - 1;
    size_t session_setup_length = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    size_t tree_connect_length = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    size_t ping_length = sizeof(DP_PING_PKT) - 1;
    uint8_t user_id[2];
    uint8_t tree_id[2];
    int result = -1;

    if (ip == NULL || port <= 0 || port > 65535) {
        return -1;
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        goto cleanup;
    }

    negotiate = (uint8_t *)malloc(negotiate_length);
    session_setup = (uint8_t *)malloc(session_setup_length);
    tree_connect = (uint8_t *)malloc(tree_connect_length);
    ping = (uint8_t *)malloc(ping_length);
    if (negotiate == NULL || session_setup == NULL ||
        tree_connect == NULL || ping == NULL) {
        goto cleanup;
    }

    memcpy(negotiate, SMB_NEGOTIATE_PKT, negotiate_length);
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, session_setup_length);
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, tree_connect_length);
    memcpy(ping, DP_PING_PKT, ping_length);

    if (doublepulsar_exchange(sock, negotiate, negotiate_length,
                              &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (doublepulsar_exchange(sock, session_setup, session_setup_length,
                              &response, &response_length) != 0 ||
        response_length < 34) {
        goto cleanup;
    }
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    if (tree_connect_length < 34) {
        goto cleanup;
    }
    tree_connect[32] = user_id[0];
    tree_connect[33] = user_id[1];

    if (doublepulsar_exchange(sock, tree_connect, tree_connect_length,
                              &response, &response_length) != 0 ||
        response_length < 30) {
        goto cleanup;
    }
    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(response);
    response = NULL;

    if (ping_length < 34) {
        goto cleanup;
    }
    ping[28] = tree_id[0];
    ping[29] = tree_id[1];
    ping[32] = user_id[0];
    ping[33] = user_id[1];

    if (doublepulsar_exchange(sock, ping, ping_length,
                              &response, &response_length) != 0 ||
        response_length <= SMB_RESP_MUX_ID_OFFSET) {
        goto cleanup;
    }

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(response);
    free(negotiate);
    free(session_setup);
    free(tree_connect);
    free(ping);
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    return result;
}