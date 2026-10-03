#include <winsock2.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int length = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
    return recv((SOCKET)sock, (char *)buf, length, 0);
}