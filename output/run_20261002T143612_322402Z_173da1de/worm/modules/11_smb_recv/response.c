#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int recv_len;
    int result;
    SOCKET socket_handle;

    if (buf_len > (size_t)INT_MAX) {
        recv_len = INT_MAX;
    } else {
        recv_len = (int)buf_len;
    }

    socket_handle = (SOCKET)(uintptr_t)(unsigned int)sock;
    result = recv(socket_handle, (char *)buf, recv_len, 0);

    return result == SOCKET_ERROR ? -1 : result;
}