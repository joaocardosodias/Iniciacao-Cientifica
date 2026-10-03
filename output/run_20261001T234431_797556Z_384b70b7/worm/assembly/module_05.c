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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE source = INVALID_HANDLE_VALUE;
    HANDLE temporary_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    PUCHAR key_object = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    LARGE_INTEGER file_size;
    ULONG key_object_length = 0;
    ULONG property_length = 0;
    ULONG encrypted_length = 0;
    size_t path_length;
    size_t suffix_length;
    size_t final_length;
    size_t plaintext_length;
    size_t output_length;
    size_t remaining;
    size_t offset;
    DWORD transferred;
    NTSTATUS status;
    int result = -1;

    if (path == NULL)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length - 1)
        return -1;

    final_length = path_length + suffix_length;
    if (final_length > SIZE_MAX - sizeof(".tmp"))
        return -1;

    final_path = (char *)malloc(final_length + 1);
    temporary_path = (char *)malloc(final_length + sizeof(".tmp"));
    if (final_path == NULL || temporary_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length);
    final_path[final_length] = '\0';
    memcpy(temporary_path, final_path, final_length);
    memcpy(temporary_path + final_length, ".tmp", sizeof(".tmp"));

    if (key == NULL || key_len != 32)
        goto cleanup;

    source = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (source == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(source, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)ULONG_MAX)
        goto cleanup;

    plaintext_length = (size_t)file_size.QuadPart;
    if (plaintext_length > SIZE_MAX - 29)
        goto cleanup;
    output_length = plaintext_length + 29;

    plaintext = (unsigned char *)malloc(plaintext_length != 0 ? plaintext_length : 1);
    output = (unsigned char *)malloc(output_length);
    if (plaintext == NULL || output == NULL)
        goto cleanup;

    offset = 0;
    while (offset < plaintext_length) {
        size_t chunk_size = plaintext_length - offset;
        DWORD chunk;

        if (chunk_size > (size_t)MAXDWORD)
            chunk_size = (size_t)MAXDWORD;
        chunk = (DWORD)chunk_size;
        if (!ReadFile(source, plaintext + offset, chunk, &transferred, NULL) ||
            transferred == 0)
            goto cleanup;
        offset += (size_t)transferred;
    }

    if (!CloseHandle(source))
        goto cleanup;
    source = INVALID_HANDLE_VALUE;

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
                               (ULONG)sizeof(key_object_length), &property_length, 0);
    if (status < 0 || property_length < sizeof(key_object_length))
        goto cleanup;

    key_object = (PUCHAR)malloc(key_object_length != 0 ? key_object_length : 1);
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

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = (ULONG)sizeof(nonce);
    auth_info.pbTag = tag;
    auth_info.cbTag = (ULONG)sizeof(tag);

    status = BCryptEncrypt(symmetric_key, plaintext, (ULONG)plaintext_length,
                           &auth_info, NULL, 0, output + 13,
                           (ULONG)plaintext_length, &encrypted_length, 0);
    if (status < 0 || encrypted_length != (ULONG)plaintext_length)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(output + 1, nonce, sizeof(nonce));
    memcpy(output + 13 + plaintext_length, tag, sizeof(tag));

    temporary_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (temporary_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    remaining = output_length;
    offset = 0;
    while (remaining != 0) {
        DWORD chunk = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;

        if (!WriteFile(temporary_file, output + offset, chunk, &transferred, NULL) ||
            transferred == 0)
            goto cleanup;
        offset += (size_t)transferred;
        remaining -= (size_t)transferred;
    }

    if (!FlushFileBuffers(temporary_file))
        goto cleanup;
    if (!CloseHandle(temporary_file)) {
        temporary_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    temporary_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temporary_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    result = 0;

cleanup:
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (temporary_file != INVALID_HANDLE_VALUE)
        CloseHandle(temporary_file);
    if (result != 0 && temporary_path != NULL)
        DeleteFileA(temporary_path);
    if (symmetric_key != NULL)
        BCryptDestroyKey(symmetric_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(plaintext);
    free(output);
    free(final_path);
    free(temporary_path);
    return result;
}