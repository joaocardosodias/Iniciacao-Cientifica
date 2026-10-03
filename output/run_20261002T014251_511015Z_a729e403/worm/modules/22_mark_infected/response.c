#include "config.h"
#include <windows.h>
#include <string.h>

int mark_infected(const char *ip)
{
    HANDLE file;
    LARGE_INTEGER zero;
    DWORD bytes_read;
    unsigned char buffer[4096];
    size_t ip_length;
    size_t line_position = 0;
    int line_mismatch = 0;
    int trailing_cr = 0;
    int found = 0;
    int have_bytes = 0;
    unsigned char last_byte = 0;
    size_t i;

    if (ip == NULL)
        return -1;

    ip_length = strlen(ip);
    for (i = 0; i < ip_length; ++i) {
        if (ip[i] == '\r' || ip[i] == '\n')
            return -1;
    }

    file = CreateFileA(SELF_MARKER, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    zero.QuadPart = 0;
    if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) {
        CloseHandle(file);
        return -1;
    }

    for (;;) {
        if (!ReadFile(file, buffer, (DWORD)sizeof(buffer), &bytes_read, NULL)) {
            CloseHandle(file);
            return -1;
        }
        if (bytes_read == 0)
            break;

        have_bytes = 1;
        last_byte = buffer[bytes_read - 1];

        for (i = 0; i < (size_t)bytes_read; ++i) {
            unsigned char byte = buffer[i];

            if (byte == '\n') {
                if (!line_mismatch &&
                    (line_position == ip_length ||
                     (trailing_cr && line_position == ip_length + 1))) {
                    found = 1;
                    break;
                }
                line_position = 0;
                line_mismatch = 0;
                trailing_cr = 0;
                continue;
            }

            if (line_mismatch)
                continue;

            if (trailing_cr) {
                line_mismatch = 1;
            } else if (line_position < ip_length) {
                if (byte != (unsigned char)ip[line_position])
                    line_mismatch = 1;
                else
                    ++line_position;
            } else if (line_position == ip_length && byte == '\r') {
                ++line_position;
                trailing_cr = 1;
            } else {
                line_mismatch = 1;
            }
        }

        if (found)
            break;
    }

    if (!found && !line_mismatch && !trailing_cr &&
        line_position == ip_length)
        found = 1;

    if (found) {
        if (!CloseHandle(file))
            return -1;
        return 1;
    }

    {
        LARGE_INTEGER end_position;
        DWORD bytes_written;

        if (!SetFilePointerEx(file, zero, &end_position, FILE_END)) {
            CloseHandle(file);
            return -1;
        }

        if (have_bytes && last_byte != '\n') {
            static const char newline = '\n';
            if (!WriteFile(file, &newline, 1, &bytes_written, NULL) ||
                bytes_written != 1) {
                CloseHandle(file);
                return -1;
            }
        }

        {
            size_t offset = 0;
            while (offset < ip_length) {
                DWORD to_write = (ip_length - offset > (size_t)0xFFFFFFFFUL)
                                    ? 0xFFFFFFFFUL
                                    : (DWORD)(ip_length - offset);
                if (!WriteFile(file, ip + offset, to_write, &bytes_written, NULL) ||
                    bytes_written == 0) {
                    CloseHandle(file);
                    return -1;
                }
                offset += bytes_written;
            }
        }

        if (!WriteFile(file, "\n", 1, &bytes_written, NULL) || bytes_written != 1) {
            CloseHandle(file);
            return -1;
        }
    }

    if (!CloseHandle(file))
        return -1;
    return 0;
}