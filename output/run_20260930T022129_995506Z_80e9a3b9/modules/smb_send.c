#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

int smb_send(int sock, const uint8_t *data, size_t len)
{
    size_t sent = 0;

    if (len != 0 && data == NULL) {
        errno = EINVAL;
        return -1;
    }

    while (sent < len) {
        size_t remaining = len - sent;
        size_t chunk = remaining > (size_t)SSIZE_MAX
            ? (size_t)SSIZE_MAX
            : remaining;
        ssize_t n = send(sock, data + sent, chunk, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}