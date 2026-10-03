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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE temp_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE encryption_key = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    unsigned char *key_object = NULL;
    char *final_path = NULL;
    char *temp_path = NULL;
    size_t plaintext_size = 0;
    size_t output_size = 0;
    size_t path_length;
    size_t suffix_length;
    size_t final_length;
    size_t offset;
    ULONG key_object_size = 0;
    ULONG property_size = 0;
    ULONG encrypted_size = 0;
    DWORD bytes_transferred;
    LARGE_INTEGER file_size;
    unsigned char nonce[12];
    NTSTATUS status;
    int result = -1;
    int temp_attempted = 0;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (suffix_length > SIZE_MAX - 5 ||
        path_length > SIZE_MAX - suffix_length - 5)
        return -1;

    final_length = path_length + suffix_length;
    final_path = (char *)malloc(final_length + 1);
    temp_path = (char *)malloc(final_length + 5);
    if (final_path == NULL || temp_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length);
    final_path[final_length] = '\0';
    memcpy(temp_path, final_path, final_length);
    memcpy(temp_path + final_length, ".tmp", 5);

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)ULONG_MAX)
        goto cleanup;

    plaintext_size = (size_t)file_size.QuadPart;
    if (plaintext_size > SIZE_MAX - 29)
        goto cleanup;

    plaintext = (unsigned char *)malloc(plaintext_size == 0 ? 1 : plaintext_size);
    if (plaintext == NULL)
        goto cleanup;

    offset = 0;
    while (offset < plaintext_size) {
        size_t remaining = plaintext_size - offset;
        DWORD request = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;

        if (!ReadFile(input_file, plaintext + offset, request, &bytes_transferred, NULL) ||
            bytes_transferred == 0)
            goto cleanup;
        offset += bytes_transferred;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&key_object_size, sizeof(key_object_size),
                               &property_size, 0);
    if (!BCRYPT_SUCCESS(status) || property_size != sizeof(key_object_size) ||
        key_object_size == 0)
        goto cleanup;

    key_object = (unsigned char *)malloc(key_object_size);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &encryption_key, key_object,
                                        key_object_size, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGenRandom(NULL, nonce, sizeof(nonce),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    output_size = plaintext_size + 29;
    output = (unsigned char *)malloc(output_size);
    if (output == NULL)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(output + 1, nonce, sizeof(nonce));

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;

        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = nonce;
        auth_info.cbNonce = sizeof(nonce);
        auth_info.pbTag = output + 13 + plaintext_size;
        auth_info.cbTag = 16;

        status = BCryptEncrypt(encryption_key, plaintext, (ULONG)plaintext_size,
                               &auth_info, NULL, 0, output + 13,
                               (ULONG)plaintext_size, &encrypted_size, 0);
        if (!BCRYPT_SUCCESS(status) || encrypted_size != (ULONG)plaintext_size)
            goto cleanup;
    }

    if (input_file != INVALID_HANDLE_VALUE) {
        CloseHandle(input_file);
        input_file = INVALID_HANDLE_VALUE;
    }

    temp_attempted = 1;
    temp_file = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (temp_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    offset = 0;
    while (offset < output_size) {
        size_t remaining = output_size - offset;
        DWORD request = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;

        if (!WriteFile(temp_file, output + offset, request, &bytes_transferred, NULL) ||
            bytes_transferred == 0)
            goto cleanup;
        offset += bytes_transferred;
    }

    if (!FlushFileBuffers(temp_file))
        goto cleanup;
    if (!CloseHandle(temp_file)) {
        temp_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    temp_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temp_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    temp_attempted = 0;
    result = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (temp_file != INVALID_HANDLE_VALUE)
        CloseHandle(temp_file);
    if (temp_attempted && temp_path != NULL)
        DeleteFileA(temp_path);
    if (encryption_key != NULL)
        BCryptDestroyKey(encryption_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(output);
    free(plaintext);
    free(temp_path);
    free(final_path);
    return result;
}