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
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE output_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE encryption_key = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *key_object = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    size_t path_length;
    size_t suffix_length;
    size_t final_path_length;
    size_t plaintext_length = 0;
    size_t output_length;
    size_t written_offset;
    LARGE_INTEGER file_size;
    ULONG key_object_length = 0;
    ULONG property_length = 0;
    ULONG encrypted_length = 0;
    DWORD bytes_read;
    DWORD bytes_written;
    NTSTATUS status;
    unsigned char nonce[12];
    unsigned char tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length - 1)
        return -1;

    final_path_length = path_length + suffix_length;
    if (final_path_length > SIZE_MAX - sizeof(".tmp"))
        return -1;

    final_path = (char *)malloc(final_path_length + 1);
    temporary_path = (char *)malloc(final_path_length + sizeof(".tmp"));
    if (final_path == NULL || temporary_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length);
    final_path[final_path_length] = '\0';
    memcpy(temporary_path, final_path, final_path_length);
    memcpy(temporary_path + final_path_length, ".tmp", sizeof(".tmp"));

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0)
        goto cleanup;
    if ((unsigned long long)file_size.QuadPart > (unsigned long long)SIZE_MAX ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)ULONG_MAX)
        goto cleanup;

    plaintext_length = (size_t)file_size.QuadPart;
    plaintext = (unsigned char *)malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (plaintext == NULL)
        goto cleanup;

    while (plaintext_length != 0) {
        size_t offset = 0;
        size_t remaining = plaintext_length;

        while (remaining != 0) {
            DWORD request = remaining > (size_t)MAXDWORD
                                ? MAXDWORD
                                : (DWORD)remaining;
            if (!ReadFile(input_file, plaintext + offset, request, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            offset += bytes_read;
            remaining -= bytes_read;
        }
        plaintext_length = offset;
        break;
    }

    if (!CloseHandle(input_file))
        goto cleanup;
    input_file = INVALID_HANDLE_VALUE;

    if (plaintext_length > SIZE_MAX - 29)
        goto cleanup;
    output_length = plaintext_length + 29;
    output = (unsigned char *)malloc(output_length);
    if (output == NULL)
        goto cleanup;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status < 0)
        goto cleanup;

    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0)
        goto cleanup;

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&key_object_length,
                               (ULONG)sizeof(key_object_length),
                               &property_length, 0);
    if (status < 0 || property_length != sizeof(key_object_length) ||
        key_object_length == 0)
        goto cleanup;

    key_object = (unsigned char *)malloc(key_object_length);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &encryption_key,
                                        key_object, key_object_length,
                                        (PUCHAR)key, (ULONG)key_len, 0);
    if (status < 0)
        goto cleanup;

    status = BCryptGenRandom(NULL, nonce, (ULONG)sizeof(nonce),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
        goto cleanup;

    memcpy(output, &(unsigned char){(unsigned char)ENCRYPTED_FORMAT_VERSION}, 1);
    memcpy(output + 1, nonce, sizeof(nonce));

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = (ULONG)sizeof(nonce);
    auth_info.pbTag = tag;
    auth_info.cbTag = (ULONG)sizeof(tag);

    status = BCryptEncrypt(encryption_key, plaintext, (ULONG)plaintext_length,
                           &auth_info, NULL, 0, output + 13,
                           (ULONG)plaintext_length, &encrypted_length, 0);
    if (status < 0 || encrypted_length != (ULONG)plaintext_length)
        goto cleanup;

    memcpy(output + 13 + plaintext_length, tag, sizeof(tag));

    output_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    written_offset = 0;
    while (written_offset < output_length) {
        size_t remaining = output_length - written_offset;
        DWORD request = remaining > (size_t)MAXDWORD
                            ? MAXDWORD
                            : (DWORD)remaining;
        if (!WriteFile(output_file, output + written_offset, request,
                       &bytes_written, NULL) ||
            bytes_written == 0)
            goto cleanup;
        written_offset += bytes_written;
    }

    if (!FlushFileBuffers(output_file))
        goto cleanup;
    if (!CloseHandle(output_file))
        goto cleanup;
    output_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temporary_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    result = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (output_file != INVALID_HANDLE_VALUE)
        CloseHandle(output_file);
    if (result != 0 && temporary_path != NULL)
        DeleteFileA(temporary_path);
    if (encryption_key != NULL)
        BCryptDestroyKey(encryption_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(output);
    free(key_object);
    free(plaintext);
    free(temporary_path);
    free(final_path);
    return result;
}