#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int smb_send_all(SOCKET sock, const unsigned char *data, size_t length)
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

static int smb_recv_all(SOCKET sock, unsigned char *data, size_t length)
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

static int smb_receive_response(SOCKET sock, size_t offset, void *output,
                                size_t output_length)
{
    unsigned char header[4];
    unsigned char prefix[64];
    unsigned char discard[4096];
    size_t payload_length;
    size_t prefix_length = 0;
    size_t remaining;

    if (smb_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)(header[1] & 0x01u) << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    if (payload_length > 0x1ffffu)
        return -1;

    if (output_length != 0) {
        if (output == NULL || offset < sizeof(header) ||
            offset > SIZE_MAX - output_length)
            return -1;

        prefix_length = offset + output_length - sizeof(header);
        if (prefix_length > sizeof(prefix) ||
            prefix_length > payload_length)
            return -1;

        if (smb_recv_all(sock, prefix, prefix_length) != 0)
            return -1;

        memcpy(output, prefix + offset - sizeof(header), output_length);
    }

    remaining = payload_length - prefix_length;
    while (remaining != 0) {
        size_t chunk = remaining > sizeof(discard) ? sizeof(discard) : remaining;
        if (smb_recv_all(sock, discard, chunk) != 0)
            return -1;
        remaining -= chunk;
    }

    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    unsigned char *negotiate = NULL;
    unsigned char *session_setup = NULL;
    unsigned char *tree_connect = NULL;
    unsigned char *ping = NULL;
    unsigned char user_id[2];
    unsigned char tree_id[2];
    unsigned char multiplex_id;
    int result = -1;

    if (ip == NULL)
        return -1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    negotiate = (unsigned char *)malloc(sizeof(SMB_NEGOTIATE_PKT));
    session_setup = (unsigned char *)malloc(sizeof(SMB_SESSION_SETUP_PKT));
    tree_connect = (unsigned char *)malloc(sizeof(SMB_TREE_CONNECT_PKT));
    ping = (unsigned char *)malloc(sizeof(DP_PING_PKT));

    if (negotiate == NULL || session_setup == NULL ||
        tree_connect == NULL || ping == NULL)
        goto cleanup;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(ping, DP_PING_PKT, sizeof(DP_PING_PKT));

    if (sizeof(SMB_NEGOTIATE_PKT) <= 1 ||
        sizeof(SMB_SESSION_SETUP_PKT) <= 1 ||
        sizeof(SMB_TREE_CONNECT_PKT) <= 1 ||
        sizeof(DP_PING_PKT) <= 1)
        goto cleanup;

    if (smb_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        smb_receive_response(sock, 0, NULL, 0) != 0)
        goto cleanup;

    if (smb_send_all(sock, session_setup, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        smb_receive_response(sock, 32, user_id, sizeof(user_id)) != 0)
        goto cleanup;

    tree_connect[32] = user_id[0];
    tree_connect[33] = user_id[1];

    if (smb_send_all(sock, tree_connect, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        smb_receive_response(sock, 28, tree_id, sizeof(tree_id)) != 0)
        goto cleanup;

    ping[28] = tree_id[0];
    ping[29] = tree_id[1];
    ping[32] = user_id[0];
    ping[33] = user_id[1];

    if (smb_send_all(sock, ping, sizeof(DP_PING_PKT) - 1) != 0 ||
        smb_receive_response(sock, SMB_RESP_MUX_ID_OFFSET,
                             &multiplex_id, sizeof(multiplex_id)) != 0)
        goto cleanup;

    result = multiplex_id == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(negotiate);
    free(session_setup);
    free(tree_connect);
    free(ping);
    closesocket(sock);
    return result;
}