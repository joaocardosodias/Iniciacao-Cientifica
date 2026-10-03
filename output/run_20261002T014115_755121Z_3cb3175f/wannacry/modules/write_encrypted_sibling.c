#include "config.h"
#include <windows.h>
#include <bcrypt.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE source = INVALID_HANDLE_VALUE;
    HANDLE temporary = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE encryption_key = NULL;
    unsigned char *key_object = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    unsigned char nonce[12];
    LARGE_INTEGER file_size;
    ULONG key_object_length = 0;
    ULONG property_result = 0;
    ULONG ciphertext_length = 0;
    size_t plaintext_length = 0;
    size_t output_length = 0;
    size_t path_length;
    size_t suffix_length;
    size_t final_length;
    size_t offset;
    BOOL success = FALSE;
    NTSTATUS status;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length)
        return -1;
    final_length = path_length + suffix_length;
    if (final_length > SIZE_MAX - 5)
        return -1;

    final_path = (char *)malloc(final_length + 1);
    temporary_path = (char *)malloc(final_length + 5);
    if (final_path == NULL || temporary_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length);
    final_path[final_length] = '\0';

    memcpy(temporary_path, final_path, final_length);
    memcpy(temporary_path + final_length, ".tmp", 5);

    source = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (source == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(source, &file_size) || file_size.QuadPart < 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)ULONG_MAX)
        goto cleanup;

    plaintext_length = (size_t)file_size.QuadPart;
    if (plaintext_length > SIZE_MAX - 29)
        goto cleanup;

    plaintext = (unsigned char *)malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (plaintext == NULL)
        goto cleanup;

    offset = 0;
    while (offset < plaintext_length) {
        DWORD bytes_read = 0;
        DWORD requested = (DWORD)(plaintext_length - offset);
        if (!ReadFile(source, plaintext + offset, requested, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        offset += bytes_read;
    }

    {
        unsigned char extra_byte;
        DWORD bytes_read = 0;
        if (!ReadFile(source, &extra_byte, 1, &bytes_read, NULL) || bytes_read != 0)
            goto cleanup;
    }

    if (!CloseHandle(source))
        goto cleanup;
    source = INVALID_HANDLE_VALUE;

    output_length = plaintext_length + 29;
    output = (unsigned char *)malloc(output_length);
    if (output == NULL)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    if (BCryptGenRandom(NULL, nonce, sizeof(nonce),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        goto cleanup;
    memcpy(output + 1, nonce, sizeof(nonce));

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
                               &property_result, 0);
    if (status < 0 || property_result < sizeof(key_object_length))
        goto cleanup;

    key_object = (unsigned char *)malloc(key_object_length == 0 ? 1 : key_object_length);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &encryption_key, key_object,
                                        key_object_length, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (status < 0)
        goto cleanup;

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = nonce;
        auth_info.cbNonce = sizeof(nonce);
        auth_info.pbTag = output + 13 + plaintext_length;
        auth_info.cbTag = 16;

        status = BCryptEncrypt(encryption_key, plaintext,
                              (ULONG)plaintext_length, &auth_info, NULL, 0,
                              output + 13, (ULONG)plaintext_length,
                              &ciphertext_length, 0);
        if (status < 0 || ciphertext_length != (ULONG)plaintext_length)
            goto cleanup;
    }

    temporary = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (temporary == INVALID_HANDLE_VALUE)
        goto cleanup;

    offset = 0;
    while (offset < output_length) {
        DWORD bytes_written = 0;
        size_t remaining = output_length - offset;
        DWORD requested = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;
        if (!WriteFile(temporary, output + offset, requested, &bytes_written, NULL) ||
            bytes_written == 0)
            goto cleanup;
        offset += bytes_written;
    }

    if (!FlushFileBuffers(temporary))
        goto cleanup;
    if (!CloseHandle(temporary))
        goto cleanup;
    temporary = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temporary_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    success = TRUE;

cleanup:
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (temporary != INVALID_HANDLE_VALUE)
        CloseHandle(temporary);
    if (encryption_key != NULL)
        BCryptDestroyKey(encryption_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(plaintext);
    free(output);
    if (!success && temporary_path != NULL)
        DeleteFileA(temporary_path);
    free(final_path);
    free(temporary_path);

    return success ? 0 : -1;
}