#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE output_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    PUCHAR key_object = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *encrypted = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    UCHAR tag[16];
    size_t plaintext_len = 0;
    size_t output_len = 0;
    size_t path_len;
    size_t suffix_len;
    size_t remaining;
    size_t offset;
    DWORD transferred;
    ULONG object_length = 0;
    ULONG property_length = 0;
    ULONG encrypted_length = 0;
    ULONG chunk;
    NTSTATUS status;
    LARGE_INTEGER file_size;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    int temporary_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (path_len > (size_t)-1 - suffix_len - 1)
        goto cleanup;

    final_path = (char *)malloc(path_len + suffix_len + 1);
    if (final_path == NULL)
        goto cleanup;
    memcpy(final_path, path, path_len);
    memcpy(final_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    if (path_len + suffix_len > (size_t)-1 - 4 - 1)
        goto cleanup;
    temporary_path = (char *)malloc(path_len + suffix_len + 4 + 1);
    if (temporary_path == NULL)
        goto cleanup;
    memcpy(temporary_path, final_path, path_len + suffix_len);
    memcpy(temporary_path + path_len + suffix_len, ".tmp", 5);

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        (ULONGLONG)file_size.QuadPart > (ULONGLONG)MAXDWORD)
        goto cleanup;

    plaintext_len = (size_t)file_size.QuadPart;
    if (plaintext_len > (size_t)-1 - 29)
        goto cleanup;
    output_len = plaintext_len + 29;

    plaintext = (unsigned char *)malloc(plaintext_len == 0 ? 1 : plaintext_len);
    encrypted = (unsigned char *)malloc(output_len);
    if (plaintext == NULL || encrypted == NULL)
        goto cleanup;

    remaining = plaintext_len;
    offset = 0;
    while (remaining != 0) {
        chunk = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;
        transferred = 0;
        if (!ReadFile(input_file, plaintext + offset, chunk, &transferred, NULL) ||
            transferred == 0)
            goto cleanup;
        offset += transferred;
        remaining -= transferred;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0)
        goto cleanup;

    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0)
        goto cleanup;

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&object_length, (ULONG)sizeof(object_length),
                               &property_length, 0);
    if (status != 0 || property_length != sizeof(object_length) || object_length == 0)
        goto cleanup;

    key_object = (PUCHAR)malloc(object_length);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &symmetric_key, key_object,
                                        object_length, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (status != 0)
        goto cleanup;

    if (BCryptGenRandom(NULL, encrypted + 1, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        goto cleanup;
    encrypted[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;

    memset(&auth_info, 0, sizeof(auth_info));
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = encrypted + 1;
    auth_info.cbNonce = 12;
    auth_info.pbTag = tag;
    auth_info.cbTag = 16;

    status = BCryptEncrypt(symmetric_key, plaintext, (ULONG)plaintext_len,
                           &auth_info, NULL, 0, encrypted + 13,
                           (ULONG)plaintext_len, &encrypted_length, 0);
    if (status != 0 || encrypted_length != (ULONG)plaintext_len)
        goto cleanup;

    memcpy(encrypted + 13 + plaintext_len, tag, sizeof(tag));

    output_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;
    temporary_created = 1;

    remaining = output_len;
    offset = 0;
    while (remaining != 0) {
        chunk = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;
        transferred = 0;
        if (!WriteFile(output_file, encrypted + offset, chunk, &transferred, NULL) ||
            transferred == 0)
            goto cleanup;
        offset += transferred;
        remaining -= transferred;
    }

    if (!CloseHandle(output_file)) {
        output_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
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
    if (symmetric_key != NULL)
        BCryptDestroyKey(symmetric_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(plaintext);
    free(encrypted);
    if (temporary_created && temporary_path != NULL)
        DeleteFileA(temporary_path);
    free(temporary_path);
    free(final_path);
    return result;
}