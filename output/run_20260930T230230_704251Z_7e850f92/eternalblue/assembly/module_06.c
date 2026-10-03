#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int doublepulsar_send_all(int fd, const unsigned char *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int doublepulsar_recv_all(int fd, unsigned char *buf, size_t len)
{
    size_t received = 0;

    while (received < len) {
        ssize_t n = recv(fd, buf + received, len - received, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        received += (size_t)n;
    }
    return 0;
}

static int doublepulsar_read_response(int fd, unsigned char **response,
                                      size_t *response_len)
{
    unsigned char header[4];

    for (;;) {
        if (doublepulsar_recv_all(fd, header, sizeof(header)) < 0)
            return -1;

        size_t payload_len = ((size_t)header[1] << 16) |
                             ((size_t)header[2] << 8) |
                             (size_t)header[3];

        if (header[0] == 0x85)
            continue;
        if (header[0] != 0x00)
            return -1;

        unsigned char *buf = malloc(payload_len + sizeof(header));
        if (buf == NULL)
            return -1;

        for (size_t i = 0; i < sizeof(header); i++)
            buf[i] = header[i];

        if (doublepulsar_recv_all(fd, buf + sizeof(header), payload_len) < 0) {
            free(buf);
            return -1;
        }

        *response = buf;
        *response_len = payload_len + sizeof(header);
        return 0;
    }
}

int doublepulsar_check(const char *ip, int port)
{
    int fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    const unsigned char *packets[] = {
        (const unsigned char *)SMB_NEGOTIATE_PKT,
        (const unsigned char *)SMB_SESSION_SETUP_PKT,
        (const unsigned char *)SMB_TREE_CONNECT_PKT,
        (const unsigned char *)DP_PING_PKT
    };
    const size_t packet_lengths[] = {
        sizeof(SMB_NEGOTIATE_PKT),
        sizeof(SMB_SESSION_SETUP_PKT),
        sizeof(SMB_TREE_CONNECT_PKT),
        sizeof(DP_PING_PKT)
    };

    int result = -1;

    for (size_t i = 0; i < sizeof(packets) / sizeof(packets[0]); i++) {
        unsigned char *response = NULL;
        size_t response_len = 0;

        if (doublepulsar_send_all(fd, packets[i], packet_lengths[i]) < 0)
            goto done;
        if (doublepulsar_read_response(fd, &response, &response_len) < 0)
            goto done;

        if (i == 3) {
            if ((size_t)SMB_RESP_MUX_ID_OFFSET + 1 >= response_len) {
                free(response);
                goto done;
            }

            uint16_t mux_id =
                (uint16_t)response[SMB_RESP_MUX_ID_OFFSET] |
                ((uint16_t)response[SMB_RESP_MUX_ID_OFFSET + 1] << 8);
            result = (mux_id == DP_MULTIPLEX_ID_PING) ? 1 : 0;
        }

        free(response);
    }

done:
    close(fd);
    return result;
}