#include "config.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

int doublepulsar_check(const char *ip, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server.sin_addr) <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint8_t negotiate_buf[sizeof(SMB_NEGOTIATE_PKT)];
    memcpy(negotiate_buf, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (send(sock, (char*)negotiate_buf, sizeof(SMB_NEGOTIATE_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint8_t resp_negotiate[4096];
    int bytes_received = recv(sock, (char*)resp_negotiate, sizeof(resp_negotiate), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint8_t session_setup_buf[sizeof(SMB_SESSION_SETUP_PKT)];
    memcpy(session_setup_buf, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (send(sock, (char*)session_setup_buf, sizeof(SMB_SESSION_SETUP_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint8_t resp_session[4096];
    bytes_received = recv(sock, (char*)resp_session, sizeof(resp_session), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint16_t user_id = *(uint16_t*)(resp_session + 32);

    uint8_t tree_connect_buf[sizeof(SMB_TREE_CONNECT_PKT)];
    memcpy(tree_connect_buf, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    *(uint16_t*)(tree_connect_buf + 32) = user_id;
    if (send(sock, (char*)tree_connect_buf, sizeof(SMB_TREE_CONNECT_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint8_t resp_tree[4096];
    bytes_received = recv(sock, (char*)resp_tree, sizeof(resp_tree), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint16_t tree_id = *(uint16_t*)(resp_tree + 28);

    uint8_t ping_buf[sizeof(DP_PING_PKT)];
    memcpy(ping_buf, DP_PING_PKT, sizeof(DP_PING_PKT));
    *(uint16_t*)(ping_buf + 28) = tree_id;
    *(uint16_t*)(ping_buf + 32) = user_id;
    if (send(sock, (char*)ping_buf, sizeof(DP_PING_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint8_t resp_ping[4096];
    bytes_received = recv(sock, (char*)resp_ping, sizeof(resp_ping), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    if (bytes_received > SMB_RESP_MUX_ID_OFFSET && resp_ping[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING) {
        closesocket(sock);
        WSACleanup();
        return 1;
    } else {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
}