#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int received;

    if (buf_len == 0)
        return 0;
    if (buf == NULL)
        return -1;

    if (buf_len > (size_t)INT_MAX)
        buf_len = (size_t)INT_MAX;

    received = recv((SOCKET)(uintptr_t)(unsigned int)sock,
                   (char *)buf, (int)buf_len, 0);
    if (received == SOCKET_ERROR)
        return -1;

    return received;
}