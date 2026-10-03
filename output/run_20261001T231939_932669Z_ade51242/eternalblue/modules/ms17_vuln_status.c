#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include "config.h"

int ms17_vuln_status(const char *ip, int port) {
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
    ZeroMemory(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (InetPtonA(AF_INET, ip, &server.sin_addr) != 1) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    const uint8_t *negotiate_pkt = SMB_NEGOTIATE_PKT;
    uint8_t negotiate_buf[sizeof(SMB_NEGOTIATE_PKT)];
    memcpy(negotiate_buf, negotiate_pkt, sizeof(negotiate_buf));
    if (send(sock, (char*)negotiate_buf, sizeof(negotiate_buf) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    char negotiate_resp[4096];
    int resp_len = recv(sock, negotiate_resp, sizeof(negotiate_resp), 0);
    if (resp_len <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint16_t user_id = *(uint16_t*)(negotiate_resp + 32);

    const uint8_t *session_pkt = SMB_SESSION_SETUP_PKT;
    uint8_t session_buf[sizeof(SMB_SESSION_SETUP_PKT)];
    memcpy(session_buf, session_pkt, sizeof(session_buf));
    *(uint16_t*)(session_buf + 32) = user_id;
    if (send(sock, (char*)session_buf, sizeof(session_buf) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    char session_resp[4096];
    resp_len = recv(sock, session_resp, sizeof(session_resp), 0);
    if (resp_len <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint16_t tree_id = *(uint16_t*)(session_resp + 28);

    const uint8_t *tree_pkt = SMB_TREE_CONNECT_PKT;
    uint8_t tree_buf[sizeof(SMB_TREE_CONNECT_PKT)];
    memcpy(tree_buf, tree_pkt, sizeof(tree_buf));
    *(uint16_t*)(tree_buf + 28) = tree_id;
    *(uint16_t*)(tree_buf + 32) = user_id;
    if (send(sock, (char*)tree_buf, sizeof(tree_buf) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    char tree_resp[4096];
    resp_len = recv(sock, tree_resp, sizeof(tree_resp), 0);
    if (resp_len <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    const uint8_t *trans_pkt = SMB_TRANS_NAMED_PIPE_PKT;
    uint8_t trans_buf[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    memcpy(trans_buf, trans_pkt, sizeof(trans_buf));
    *(uint16_t*)(trans_buf + 28) = tree_id;
    *(uint16_t*)(trans_buf + 32) = user_id;
    if (send(sock, (char*)trans_buf, sizeof(trans_buf) - 1, 0) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    char final_resp[4096];
    resp_len = recv(sock, final_resp, sizeof(final_resp), 0);
    if (resp_len <= 0) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    uint32_t nt_status = *(uint32_t*)(final_resp + SMB_RESP_NT_STATUS_OFFSET);
    if (nt_status == NT_STATUS_INSUFF_SERVER_RESOURCES) {
        closesocket(sock);
        WSACleanup();
        return 1;
    } else {
        closesocket(sock);
        WSACleanup();
        return 0;
    }
}