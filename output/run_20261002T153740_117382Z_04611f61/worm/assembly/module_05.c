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
#include "config.h"
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE output_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    unsigned char *key_object = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    unsigned char nonce[12];
    unsigned char crypto_nonce[12];
    unsigned char tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    LARGE_INTEGER file_size;
    ULONG key_object_length = 0;
    ULONG ciphertext_length = 0;
    size_t plaintext_length = 0;
    size_t output_length = 0;
    size_t path_length;
    size_t suffix_length;
    size_t offset;
    int temporary_created = 0;
    int result = -1;
    NTSTATUS status;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length - 1)
        return -1;

    final_path = (char *)malloc(path_length + suffix_length + 1);
    if (final_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length + 1);

    if (path_length + suffix_length > SIZE_MAX - 5)
        goto cleanup;

    temporary_path = (char *)malloc(path_length + suffix_length + 5);
    if (temporary_path == NULL)
        goto cleanup;

    memcpy(temporary_path, final_path, path_length + suffix_length);
    memcpy(temporary_path + path_length + suffix_length, ".tmp", 5);

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)ULONG_MAX)
        goto cleanup;

    plaintext_length = (size_t)file_size.QuadPart;
    plaintext = (unsigned char *)malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (plaintext == NULL)
        goto cleanup;

    offset = 0;
    while (offset < plaintext_length) {
        DWORD bytes_to_read = (DWORD)(plaintext_length - offset);
        DWORD bytes_read = 0;
        if (!ReadFile(input_file, plaintext + offset, bytes_to_read, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        offset += bytes_read;
    }

    if (!CloseHandle(input_file))
        goto cleanup;
    input_file = INVALID_HANDLE_VALUE;

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
                               (ULONG)sizeof(key_object_length), &key_object_length, 0);
    if (status < 0 || key_object_length == 0)
        goto cleanup;

    key_object = (unsigned char *)malloc(key_object_length);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &symmetric_key, key_object,
                                        key_object_length, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (status < 0)
        goto cleanup;

    status = BCryptGenRandom(NULL, nonce, (ULONG)sizeof(nonce),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
        goto cleanup;

    memcpy(crypto_nonce, nonce, sizeof(nonce));
    ciphertext = (unsigned char *)malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (ciphertext == NULL)
        goto cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = crypto_nonce;
    auth_info.cbNonce = (ULONG)sizeof(crypto_nonce);
    auth_info.pbTag = tag;
    auth_info.cbTag = (ULONG)sizeof(tag);

    status = BCryptEncrypt(symmetric_key, plaintext, (ULONG)plaintext_length,
                           &auth_info, NULL, 0, ciphertext,
                           (ULONG)(plaintext_length == 0 ? 1 : plaintext_length),
                           &ciphertext_length, 0);
    if (status < 0 || ciphertext_length != (ULONG)plaintext_length)
        goto cleanup;

    if (plaintext_length > SIZE_MAX - 29)
        goto cleanup;
    output_length = plaintext_length + 29;
    output = (unsigned char *)malloc(output_length);
    if (output == NULL)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(output + 1, nonce, sizeof(nonce));
    if (plaintext_length != 0)
        memcpy(output + 13, ciphertext, plaintext_length);
    memcpy(output + 13 + plaintext_length, tag, sizeof(tag));

    output_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;
    temporary_created = 1;

    offset = 0;
    while (offset < output_length) {
        DWORD bytes_to_write = (DWORD)(output_length - offset);
        DWORD bytes_written = 0;
        if (!WriteFile(output_file, output + offset, bytes_to_write, &bytes_written, NULL) ||
            bytes_written == 0)
            goto cleanup;
        offset += bytes_written;
    }

    if (!FlushFileBuffers(output_file))
        goto cleanup;
    if (!CloseHandle(output_file))
        goto cleanup;
    output_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temporary_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    temporary_created = 0;
    result = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (output_file != INVALID_HANDLE_VALUE)
        CloseHandle(output_file);
    if (temporary_created && temporary_path != NULL)
        DeleteFileA(temporary_path);
    if (symmetric_key != NULL)
        BCryptDestroyKey(symmetric_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(plaintext);
    free(ciphertext);
    free(output);
    free(final_path);
    free(temporary_path);
    return result;
}