#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    size_t len = buf_len > (size_t)INT_MAX ? (size_t)INT_MAX : buf_len;
    ssize_t received;

    do {
        received = recv(sock, buf, len, 0);
    } while (received < 0 && errno == EINTR);

    return received < 0 ? -1 : (int)received;
}