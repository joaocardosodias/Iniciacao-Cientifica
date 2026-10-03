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
    const char *text = NOTICE_TEXT;
    HANDLE file;
    size_t offset;
    int result = -1;

    if (directory == NULL || directory[0] == '\0')
        return -1;

    directory_length = strlen(directory);
    filename_length = strlen(NOTICE_FILENAME);
    text_length = strlen(text);

    if (directory_length > SIZE_MAX - filename_length - 2)
        return -1;

    path_length = directory_length + 1 + filename_length;
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
        DWORD chunk = (text_length - offset > MAXDWORD)
                          ? MAXDWORD
                          : (DWORD)(text_length - offset);
        DWORD written = 0;

        if (!WriteFile(file, text + offset, chunk, &written, NULL) ||
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