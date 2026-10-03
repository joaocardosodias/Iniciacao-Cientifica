#include "config.h"
#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    const size_t nonce_len = 12;
    const size_t tag_len = 16;
    const size_t header_len = 13;
    const size_t trailer_len = 16;
    const char suffix[] = ENCRYPTED_SUFFIX;
    const char temporary_suffix[] = ".tmp";
    char *final_path = NULL;
    char *temporary_path = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    unsigned char *key_object = NULL;
    ULONG key_object_len = 0;
    ULONG plaintext_len = 0;
    ULONG bytes_written = 0;
    ULONG encrypted_len = 0;
    DWORD property_len = 0;
    DWORD chunk = 0;
    size_t path_len;
    size_t final_len;
    size_t temporary_len;
    size_t output_len;
    size_t offset;
    LARGE_INTEGER file_size;
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE temporary_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    NTSTATUS status;
    int result = -1;

    if (path == NULL) {
        return -1;
    }

    path_len = strlen(path);
    if (path_len > SIZE_MAX - (sizeof(suffix) - 1) - 1) {
        return -1;
    }
    final_len = path_len + sizeof(suffix) - 1;
    if (final_len > SIZE_MAX - (sizeof(temporary_suffix) - 1) - 1) {
        return -1;
    }
    temporary_len = final_len + sizeof(temporary_suffix) - 1;

    final_path = (char *)malloc(final_len + 1);
    temporary_path = (char *)malloc(temporary_len + 1);
    if (final_path == NULL || temporary_path == NULL) {
        goto cleanup;
    }

    memcpy(final_path, path, path_len);
    memcpy(final_path + path_len, suffix, sizeof(suffix));
    memcpy(temporary_path, final_path, final_len);
    memcpy(temporary_path + final_len, temporary_suffix, sizeof(temporary_suffix));

    if (key == NULL || key_len != 32) {
        goto cleanup;
    }

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        file_size.QuadPart > (LONGLONG)ULONG_MAX) {
        goto cleanup;
    }
    plaintext_len = (ULONG)file_size.QuadPart;

    plaintext = (unsigned char *)malloc(plaintext_len == 0 ? 1 : (size_t)plaintext_len);
    if (plaintext == NULL) {
        goto cleanup;
    }

    offset = 0;
    while (offset < (size_t)plaintext_len) {
        size_t remaining = (size_t)plaintext_len - offset;
        chunk = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        if (!ReadFile(input_file, plaintext + offset, chunk, &bytes_written, NULL) ||
            bytes_written == 0) {
            goto cleanup;
        }
        offset += bytes_written;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    if ((size_t)plaintext_len > SIZE_MAX - header_len - trailer_len) {
        goto cleanup;
    }
    output_len = header_len + (size_t)plaintext_len + trailer_len;
    output = (unsigned char *)malloc(output_len);
    if (output == NULL) {
        goto cleanup;
    }

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status < 0) {
        goto cleanup;
    }

    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) {
        goto cleanup;
    }

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&key_object_len, sizeof(key_object_len),
                               &property_len, 0);
    if (status < 0 || property_len != sizeof(key_object_len)) {
        goto cleanup;
    }

    key_object = (unsigned char *)malloc(key_object_len == 0 ? 1 : key_object_len);
    if (key_object == NULL) {
        goto cleanup;
    }

    status = BCryptGenerateSymmetricKey(algorithm, &symmetric_key, key_object,
                                        key_object_len, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (status < 0) {
        goto cleanup;
    }

    status = BCryptGenRandom(NULL, output + 1, (ULONG)nonce_len,
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) {
        goto cleanup;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = output + 1;
    auth_info.cbNonce = (ULONG)nonce_len;
    auth_info.pbTag = output + header_len + (size_t)plaintext_len;
    auth_info.cbTag = (ULONG)tag_len;

    status = BCryptEncrypt(symmetric_key, plaintext, plaintext_len, &auth_info,
                           NULL, 0, output + header_len, plaintext_len,
                           &encrypted_len, 0);
    if (status < 0 || encrypted_len != plaintext_len) {
        goto cleanup;
    }

    temporary_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (temporary_file == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    offset = 0;
    while (offset < output_len) {
        size_t remaining = output_len - offset;
        chunk = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        if (!WriteFile(temporary_file, output + offset, chunk, &bytes_written, NULL) ||
            bytes_written == 0) {
            goto cleanup;
        }
        offset += bytes_written;
    }

    if (!FlushFileBuffers(temporary_file)) {
        goto cleanup;
    }
    if (!CloseHandle(temporary_file)) {
        temporary_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    temporary_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temporary_path, final_path, MOVEFILE_REPLACE_EXISTING)) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE) {
        CloseHandle(input_file);
    }
    if (temporary_file != INVALID_HANDLE_VALUE) {
        CloseHandle(temporary_file);
    }
    if (result != 0 && temporary_path != NULL) {
        DeleteFileA(temporary_path);
    }
    if (symmetric_key != NULL) {
        BCryptDestroyKey(symmetric_key);
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (key_object != NULL) {
        SecureZeroMemory(key_object, key_object_len);
        free(key_object);
    }
    if (plaintext != NULL) {
        SecureZeroMemory(plaintext, plaintext_len);
        free(plaintext);
    }
    if (output != NULL) {
        SecureZeroMemory(output, output_len);
        free(output);
    }
    free(temporary_path);
    free(final_path);
    return result;
}