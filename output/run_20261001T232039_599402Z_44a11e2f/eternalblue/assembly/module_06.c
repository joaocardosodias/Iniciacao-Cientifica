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
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET sock, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);

        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
            return -1;
        }
        if (result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_exact(SOCKET sock, unsigned char *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);

        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
            return -1;
        }
        if (result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_smb_frame(SOCKET sock, unsigned char response[35])
{
    unsigned char header[4];
    unsigned char discard[4096];
    size_t frame_length;
    size_t remaining;

    if (doublepulsar_recv_exact(sock, header, sizeof(header)) != 0) {
        return -1;
    }

    frame_length = ((size_t)header[1] << 16) |
                   ((size_t)header[2] << 8) |
                   (size_t)header[3];
    if (frame_length < 31) {
        return -1;
    }

    memcpy(response, header, sizeof(header));
    if (doublepulsar_recv_exact(sock, response + sizeof(header), 31) != 0) {
        return -1;
    }

    remaining = frame_length - 31;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(discard) ? remaining : sizeof(discard);
        if (doublepulsar_recv_exact(sock, discard, chunk) != 0) {
            return -1;
        }
        remaining -= chunk;
    }

    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock;
    unsigned char packet[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char response[35];
    unsigned char user_id[2];
    unsigned char tree_id[2];
    int result = -1;

    if (ip == NULL) {
        return -1;
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    memcpy(packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (doublepulsar_send_all(sock, packet, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_frame(sock, response) != 0) {
        goto done;
    }

    memcpy(packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (doublepulsar_send_all(sock, packet, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_frame(sock, response) != 0) {
        goto done;
    }
    memcpy(user_id, response + 32, sizeof(user_id));

    memcpy(packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(packet + 32, user_id, sizeof(user_id));
    if (doublepulsar_send_all(sock, packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_frame(sock, response) != 0) {
        goto done;
    }
    memcpy(tree_id, response + 28, sizeof(tree_id));

    memcpy(packet, DP_PING_PKT, sizeof(DP_PING_PKT));
    memcpy(packet + 28, tree_id, sizeof(tree_id));
    memcpy(packet + 32, user_id, sizeof(user_id));
    if (doublepulsar_send_all(sock, packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_frame(sock, response) != 0) {
        goto done;
    }

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

done:
    closesocket(sock);
    return result;
}