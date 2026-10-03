#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    SOCKET socket_handle;
    int receive_len;
    int result;

    if (buf_len == 0)
        return 0;
    if (buf == NULL || sock < 0)
        return -1;

    socket_handle = (SOCKET)(uintptr_t)(unsigned int)sock;
    receive_len = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;

    do {
        result = recv(socket_handle, (char *)buf, receive_len, 0);
    } while (result == SOCKET_ERROR && WSAGetLastError() == WSAEINTR);

    return result == SOCKET_ERROR ? -1 : result;
}