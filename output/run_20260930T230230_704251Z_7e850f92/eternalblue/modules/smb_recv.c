#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    if (buf_len > (size_t)INT_MAX)
        buf_len = (size_t)INT_MAX;

    ssize_t received;
    do {
        received = recv(sock, buf, buf_len, 0);
    } while (received < 0 && errno == EINTR);

    if (received < 0)
        return -1;

    return (int)received;
}