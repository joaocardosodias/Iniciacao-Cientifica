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

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER file_size;
    BYTE zero_buffer[65536] = {0};
    ULONGLONG remaining;
    int result = -1;

    if (path == NULL || path[0] == '\0')
        return -1;

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    if (GetFileSizeEx(file, &file_size) && file_size.QuadPart >= 0) {
        remaining = (ULONGLONG)file_size.QuadPart;
        result = 0;

        while (remaining > 0) {
            DWORD chunk = remaining > sizeof(zero_buffer)
                              ? (DWORD)sizeof(zero_buffer)
                              : (DWORD)remaining;
            DWORD written = 0;

            if (!WriteFile(file, zero_buffer, chunk, &written, NULL) ||
                written == 0) {
                result = -1;
                break;
            }
            remaining -= written;
        }
    }

    if (!CloseHandle(file))
        result = -1;

    if (result == 0 && !DeleteFileA(path))
        result = -1;

    return result;
}