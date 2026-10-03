#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len) {
    int bytes_received = recv((SOCKET)sock, (char*)buf, (int)buf_len, 0);
    if (bytes_received == 0) {
        return 0;
    } else if (bytes_received == -1) {
        return -1;
    } else {
        return bytes_received;
    }
}