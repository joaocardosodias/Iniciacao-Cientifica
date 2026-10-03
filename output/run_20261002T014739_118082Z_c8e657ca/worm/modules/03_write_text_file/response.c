#include <windows.h>
#include <string.h>

int write_text_file(const char *path, const char *text)
{
    HANDLE file;
    size_t length;
    size_t offset = 0;
    int result = 0;

    if (path == NULL || text == NULL)
        return -1;

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    length = strlen(text);
    while (offset < length) {
        DWORD chunk = length - offset > (size_t)MAXDWORD
                    ? MAXDWORD
                    : (DWORD)(length - offset);
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