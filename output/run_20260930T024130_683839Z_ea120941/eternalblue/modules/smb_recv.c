#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    size_t request = buf_len > (size_t)INT_MAX ? (size_t)INT_MAX : buf_len;
    ssize_t received;

    do {
        received = recv(sock, buf, request, 0);
    } while (received < 0 && errno == EINTR);

    return received < 0 ? -1 : (int)received;
}