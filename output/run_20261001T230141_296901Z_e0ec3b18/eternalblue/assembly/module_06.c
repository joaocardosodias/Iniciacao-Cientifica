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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET sock, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int chunk = length - sent > (size_t)INT_MAX
                        ? INT_MAX
                        : (int)(length - sent);
        int result = send(sock, (const char *)data + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int doublepulsar_receive_response(SOCKET sock, unsigned char **response,
                                         size_t *response_length)
{
    unsigned char header[4];
    size_t received = 0;
    size_t body_length;
    unsigned char *buffer;

    while (received < sizeof(header)) {
        int result = recv(sock, (char *)header + received,
                          (int)(sizeof(header) - received), 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    if (body_length == 0 || body_length > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (unsigned char *)malloc(sizeof(header) + body_length);
    if (buffer == NULL)
        return -1;
    memcpy(buffer, header, sizeof(header));

    received = 0;
    while (received < body_length) {
        size_t remaining = body_length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)buffer + sizeof(header) + received,
                          chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            free(buffer);
            return -1;
        }
        received += (size_t)result;
    }

    *response = buffer;
    *response_length = sizeof(header) + body_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    unsigned char negotiate[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char ping[sizeof(DP_PING_PKT)];
    unsigned char *response = NULL;
    size_t response_length = 0;
    unsigned char user_id_low;
    unsigned char user_id_high;
    unsigned char tree_id_low;
    unsigned char tree_id_high;
    SOCKET sock;
    int result = -1;
    int active = 0;

    if (ip == NULL)
        return -1;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(negotiate));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(session_setup));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(tree_connect));
    memcpy(ping, DP_PING_PKT, sizeof(ping));

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    if (doublepulsar_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        doublepulsar_receive_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (doublepulsar_send_all(sock, session_setup,
                              sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        doublepulsar_receive_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 33)
        goto cleanup;
    user_id_low = response[32];
    user_id_high = response[33];
    free(response);
    response = NULL;

    tree_connect[32] = user_id_low;
    tree_connect[33] = user_id_high;
    if (doublepulsar_send_all(sock, tree_connect,
                              sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        doublepulsar_receive_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 33)
        goto cleanup;
    tree_id_low = response[28];
    tree_id_high = response[29];
    user_id_low = response[32];
    user_id_high = response[33];
    free(response);
    response = NULL;

    ping[28] = tree_id_low;
    ping[29] = tree_id_high;
    ping[32] = user_id_low;
    ping[33] = user_id_high;
    if (doublepulsar_send_all(sock, ping, sizeof(DP_PING_PKT) - 1) != 0 ||
        doublepulsar_receive_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= SMB_RESP_MUX_ID_OFFSET)
        goto cleanup;

    active = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING;
    result = active ? 1 : 0;

cleanup:
    free(response);
    if (closesocket(sock) == SOCKET_ERROR)
        return -1;
    return result;
}