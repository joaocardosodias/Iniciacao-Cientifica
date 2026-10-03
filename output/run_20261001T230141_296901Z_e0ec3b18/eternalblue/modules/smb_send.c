#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>

int smb_send(int sock, const uint8_t *data, size_t len)
{
    SOCKET socket_handle;
    size_t sent_total = 0;

    if (sock < 0 || (data == NULL && len != 0))
        return -1;

    socket_handle = (SOCKET)(uintptr_t)(unsigned int)sock;

    while (sent_total < len) {
        size_t remaining = len - sent_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(socket_handle, (const char *)data + sent_total, chunk, 0);

        if (sent == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }

        if (sent == 0)
            return -1;

        sent_total += (size_t)sent;
    }

    return 0;
}