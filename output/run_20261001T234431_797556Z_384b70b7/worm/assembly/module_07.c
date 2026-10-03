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
    size_t separator_length;
    size_t path_length;
    char *path;
    HANDLE file;
    size_t written_total = 0;
    int result = -1;

    if (directory == NULL || directory[0] == '\0')
        return -1;

    directory_length = strlen(directory);
    filename_length = strlen(NOTICE_FILENAME);
    text_length = strlen(NOTICE_TEXT);
    separator_length = (directory[directory_length - 1] == '\\' ||
                        directory[directory_length - 1] == '/') ? 0 : 1;

    if (directory_length > SIZE_MAX - separator_length ||
        directory_length + separator_length > SIZE_MAX - filename_length ||
        directory_length + separator_length + filename_length == SIZE_MAX)
        return -1;

    path_length = directory_length + separator_length + filename_length;
    path = (char *)malloc(path_length + 1);
    if (path == NULL)
        return -1;

    memcpy(path, directory, directory_length);
    if (separator_length != 0)
        path[directory_length] = '\\';
    memcpy(path + directory_length + separator_length, NOTICE_FILENAME, filename_length);
    path[path_length] = '\0';

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    free(path);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    while (written_total < text_length) {
        size_t remaining = text_length - written_total;
        DWORD bytes_to_write = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;
        DWORD bytes_written = 0;

        if (!WriteFile(file, NOTICE_TEXT + written_total, bytes_to_write,
                       &bytes_written, NULL) || bytes_written == 0)
            goto cleanup;

        written_total += bytes_written;
    }

    result = 0;

cleanup:
    if (!CloseHandle(file))
        result = -1;

    return result;
}