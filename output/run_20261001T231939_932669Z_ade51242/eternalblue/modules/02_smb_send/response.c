#include "config.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <limits.h>
#pragma comment(lib, "ws2_32.lib")

int smb_send(int sock, const uint8_t *data, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        size_t bytes_to_send = len - total_sent;
        if (bytes_to_send > INT_MAX) {
            bytes_to_send = INT_MAX;
        }
        int bytes_sent = send(sock, (const char*)data + total_sent, (int)bytes_to_send, 0);
        if (bytes_sent == -1) {
            return -1;
        }
        if (bytes_sent == 0) {
            return -1;
        }
        total_sent += bytes_sent;
    }
    return 0;
}