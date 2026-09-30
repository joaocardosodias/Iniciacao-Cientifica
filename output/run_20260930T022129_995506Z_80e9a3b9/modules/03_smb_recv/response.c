#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    if (buf_len > (size_t)INT_MAX)
        buf_len = (size_t)INT_MAX;

    return (int)recv(sock, buf, buf_len, 0);
}