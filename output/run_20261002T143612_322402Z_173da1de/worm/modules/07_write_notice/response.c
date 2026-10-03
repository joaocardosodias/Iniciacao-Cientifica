#include "config.h"
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int write_notice(const char *directory)
{
    size_t directory_length;
    size_t filename_length;
    size_t text_length;
    size_t path_length;
    size_t offset;
    char *path;
    HANDLE file;
    int result = -1;

    if (directory == NULL)
        return -1;

    directory_length = strlen(directory);
    filename_length = strlen(NOTICE_FILENAME);
    text_length = strlen(NOTICE_TEXT);

    if (filename_length > SIZE_MAX - 2 ||
        directory_length > SIZE_MAX - filename_length - 2)
        return -1;

    path_length = directory_length + 1 + filename_length;
    if (path_length == SIZE_MAX)
        return -1;

    path = (char *)malloc(path_length + 1);
    if (path == NULL)
        return -1;

    memcpy(path, directory, directory_length);
    path[directory_length] = '\\';
    memcpy(path + directory_length + 1, NOTICE_FILENAME, filename_length);
    path[path_length] = '\0';

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    free(path);

    if (file == INVALID_HANDLE_VALUE)
        return -1;

    offset = 0;
    result = 0;
    while (offset < text_length) {
        size_t remaining = text_length - offset;
        DWORD chunk = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, NOTICE_TEXT + offset, chunk, &written, NULL) ||
            written == 0) {
            result = -1;
            break;
        }

        offset += written;
    }

    if (!CloseHandle(file))
        result = -1;

    return result;
}