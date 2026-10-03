#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int received;
    int length;

    if (sock < 0 || (buf == NULL && buf_len != 0))
        return -1;

    if (buf_len == 0)
        return 0;

    length = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
    received = recv((SOCKET)(unsigned int)sock, (char *)buf, length, 0);

    return received == SOCKET_ERROR ? -1 : received;
}