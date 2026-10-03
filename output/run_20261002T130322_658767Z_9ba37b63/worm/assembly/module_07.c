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
#include <stdlib.h>
#include <string.h>
#include "config.h"

int write_notice(const char *directory)
{
    size_t directory_length;
    size_t filename_length;
    size_t text_length;
    size_t max_size = (size_t)-1;
    size_t remaining;
    size_t offset;
    char *path;
    HANDLE file;
    int result = -1;

    if (directory == NULL)
        return -1;

    directory_length = strlen(directory);
    filename_length = strlen(NOTICE_FILENAME);
    text_length = strlen(NOTICE_TEXT);

    if (directory_length > max_size - 2 ||
        filename_length > max_size - directory_length - 2)
        return -1;

    path = (char *)malloc(directory_length + filename_length + 2);
    if (path == NULL)
        return -1;

    memcpy(path, directory, directory_length);
    path[directory_length] = '\\';
    memcpy(path + directory_length + 1, NOTICE_FILENAME, filename_length + 1);

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    free(path);

    if (file == INVALID_HANDLE_VALUE)
        return -1;

    result = 0;
    offset = 0;
    remaining = text_length;

    while (remaining != 0) {
        DWORD chunk = remaining > (size_t)MAXDWORD
                          ? MAXDWORD
                          : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, NOTICE_TEXT + offset, chunk, &written, NULL) ||
            written == 0) {
            result = -1;
            break;
        }

        offset += written;
        remaining -= written;
    }

    if (!CloseHandle(file))
        result = -1;

    return result;
}