#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <stdlib.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET sock, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_all(SOCKET sock, unsigned char *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_frame(SOCKET sock, unsigned char **frame, size_t *frame_length)
{
    unsigned char header[4];

    for (;;) {
        if (doublepulsar_recv_all(sock, header, sizeof(header)) != 0) {
            return -1;
        }

        size_t payload_length = ((size_t)header[1] << 16) |
                                ((size_t)header[2] << 8) |
                                (size_t)header[3];

        if (header[0] == 0x85 && payload_length == 0) {
            continue;
        }
        if (header[0] != 0x00 || payload_length == 0) {
            return -1;
        }

        unsigned char *buffer = (unsigned char *)malloc(payload_length + sizeof(header));
        if (buffer == NULL) {
            return -1;
        }

        for (size_t i = 0; i < sizeof(header); ++i) {
            buffer[i] = header[i];
        }

        if (doublepulsar_recv_all(sock, buffer + sizeof(header), payload_length) != 0) {
            free(buffer);
            return -1;
        }

        *frame = buffer;
        *frame_length = payload_length + sizeof(header);
        return 0;
    }
}

int doublepulsar_check(const char *ip, int port)
{
    if (ip == NULL) {
        return -1;
    }

    SOCKET sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    const unsigned char *packets[] = {
        (const unsigned char *)SMB_NEGOTIATE_PKT,
        (const unsigned char *)SMB_SESSION_SETUP_PKT,
        (const unsigned char *)SMB_TREE_CONNECT_PKT,
        (const unsigned char *)DP_PING_PKT
    };
    const size_t packet_lengths[] = {
        sizeof(SMB_NEGOTIATE_PKT),
        sizeof(SMB_SESSION_SETUP_PKT),
        sizeof(SMB_TREE_CONNECT_PKT),
        sizeof(DP_PING_PKT)
    };

    int result = -1;
    unsigned char *response = NULL;
    size_t response_length = 0;

    for (size_t i = 0; i < sizeof(packet_lengths) / sizeof(packet_lengths[0]); ++i) {
        if (doublepulsar_send_all(sock, packets[i], packet_lengths[i]) != 0 ||
            doublepulsar_recv_frame(sock, &response, &response_length) != 0) {
            goto cleanup;
        }

        if (i + 1 < sizeof(packet_lengths) / sizeof(packet_lengths[0])) {
            free(response);
            response = NULL;
            response_length = 0;
        }
    }

    if ((size_t)SMB_RESP_MUX_ID_OFFSET + 2 > response_length) {
        goto cleanup;
    }

    {
        unsigned int multiplex_id =
            (unsigned int)response[SMB_RESP_MUX_ID_OFFSET] |
            ((unsigned int)response[SMB_RESP_MUX_ID_OFFSET + 1] << 8);
        result = multiplex_id == DP_MULTIPLEX_ID_PING ? 1 : 0;
    }

cleanup:
    free(response);
    closesocket(sock);
    return result;
}