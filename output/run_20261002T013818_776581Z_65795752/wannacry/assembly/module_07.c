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
    char *path;
    HANDLE file;
    size_t written_total = 0;
    int result = 0;

    if (directory == NULL)
        return -1;

    directory_length = strlen(directory);
    filename_length = strlen(NOTICE_FILENAME);
    text_length = strlen(NOTICE_TEXT);

    if (filename_length > SIZE_MAX - 2 ||
        directory_length > SIZE_MAX - filename_length - 2)
        return -1;

    path_length = directory_length + 1 + filename_length + 1;
    path = (char *)malloc(path_length);
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

    while (written_total < text_length) {
        size_t remaining = text_length - written_total;
        DWORD to_write = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, NOTICE_TEXT + written_total, to_write, &written, NULL) ||
            written == 0) {
            result = -1;
            break;
        }
        written_total += written;
    }

    if (!CloseHandle(file))
        result = -1;

    return result;
}