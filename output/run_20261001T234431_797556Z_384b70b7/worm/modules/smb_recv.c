#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int recv_len;
    int result;

    if (buf_len == 0)
        return 0;
    if (buf == NULL)
        return -1;

    recv_len = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
    result = recv((SOCKET)(uintptr_t)(unsigned int)sock, (char *)buf, recv_len, 0);

    return result == SOCKET_ERROR ? -1 : result;
}