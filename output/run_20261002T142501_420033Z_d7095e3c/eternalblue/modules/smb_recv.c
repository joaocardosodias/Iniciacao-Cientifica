#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int length;
    int received;

    if (buf_len != 0 && buf == NULL) {
        return -1;
    }

    length = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
    received = recv((SOCKET)sock, (char *)buf, length, 0);
    if (received == SOCKET_ERROR) {
        return -1;
    }

    return received;
}