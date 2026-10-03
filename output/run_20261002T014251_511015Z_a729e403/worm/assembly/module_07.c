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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int write_notice(const char *directory)
{
    size_t directory_length;
    size_t filename_length;
    size_t text_length;
    size_t path_length;
    size_t offset;
    size_t remaining;
    char *path;
    HANDLE file;
    int success = 1;

    if (directory == NULL)
        return -1;

    directory_length = strlen(directory);
    filename_length = strlen(NOTICE_FILENAME);
    text_length = strlen(NOTICE_TEXT);

    if (directory_length == 0 ||
        filename_length > SIZE_MAX - 2 ||
        directory_length > SIZE_MAX - filename_length - 2)
        return -1;

    path_length = directory_length + filename_length + 1;
    path = (char *)malloc(path_length + 1);
    if (path == NULL)
        return -1;

    memcpy(path, directory, directory_length);
    offset = directory_length;
    if (path[offset - 1] != '\\' && path[offset - 1] != '/')
        path[offset++] = '\\';
    memcpy(path + offset, NOTICE_FILENAME, filename_length);
    path[offset + filename_length] = '\0';

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    free(path);

    if (file == INVALID_HANDLE_VALUE)
        return -1;

    remaining = text_length;
    offset = 0;
    while (remaining > 0) {
        DWORD chunk = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, NOTICE_TEXT + offset, chunk, &written, NULL) ||
            written == 0) {
            success = 0;
            break;
        }

        offset += written;
        remaining -= written;
    }

    if (!CloseHandle(file))
        success = 0;

    return success ? 0 : -1;
}