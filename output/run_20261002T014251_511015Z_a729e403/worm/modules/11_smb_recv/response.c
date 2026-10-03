#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int result;
    int receive_len;

    if (buf_len == 0) {
        return 0;
    }

    if (buf == NULL) {
        return -1;
    }

    receive_len = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
    result = recv((SOCKET)(uintptr_t)(unsigned int)sock, (char *)buf, receive_len, 0);

    return result == SOCKET_ERROR ? -1 : result;
}