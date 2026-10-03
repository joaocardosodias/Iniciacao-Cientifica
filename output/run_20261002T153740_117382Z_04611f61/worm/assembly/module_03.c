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

int write_text_file(const char *path, const char *text)
{
    HANDLE file;
    size_t remaining;
    const char *cursor;
    int result = 0;

    if (path == NULL || text == NULL)
        return -1;

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    remaining = strlen(text);
    cursor = text;

    while (remaining > 0) {
        DWORD chunk = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, cursor, chunk, &written, NULL) ||
            written == 0 || written > chunk) {
            result = -1;
            break;
        }

        cursor += written;
        remaining -= written;
    }

    if (!CloseHandle(file))
        result = -1;

    return result;
}