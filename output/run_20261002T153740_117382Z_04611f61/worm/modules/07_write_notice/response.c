#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int write_notice(const char *directory)
{
    const char *filename = NOTICE_FILENAME;
    const char *text = NOTICE_TEXT;
    size_t directory_length;
    size_t filename_length;
    size_t text_length;
    size_t path_length;
    char *path;
    HANDLE file;
    size_t written_total = 0;
    int result = -1;

    if (directory == NULL)
        return -1;

    directory_length = strlen(directory);
    filename_length = strlen(filename);
    text_length = strlen(text);

    if (filename_length > SIZE_MAX - 2 ||
        directory_length > SIZE_MAX - filename_length - 2)
        return -1;

    path_length = directory_length + 1 + filename_length;
    path = (char *)malloc(path_length + 1);
    if (path == NULL)
        return -1;

    memcpy(path, directory, directory_length);
    path[directory_length] = '\\';
    memcpy(path + directory_length + 1, filename, filename_length + 1);

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        free(path);
        return -1;
    }

    result = 0;
    while (written_total < text_length) {
        size_t remaining = text_length - written_total;
        DWORD chunk = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;
        DWORD bytes_written = 0;

        if (!WriteFile(file, text + written_total, chunk, &bytes_written, NULL) ||
            bytes_written == 0) {
            result = -1;
            break;
        }
        written_total += bytes_written;
    }

    if (!CloseHandle(file))
        result = -1;

    free(path);
    return result;
}