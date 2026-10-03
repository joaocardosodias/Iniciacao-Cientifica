#include <windows.h>
#include <string.h>

int write_text_file(const char *path, const char *text)
{
    HANDLE file;
    size_t remaining;
    const char *current;
    int result = 0;

    if (path == NULL || text == NULL) {
        return -1;
    }

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    current = text;
    remaining = strlen(text);

    while (remaining > 0) {
        DWORD chunk = remaining > (size_t)MAXDWORD
                          ? MAXDWORD
                          : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, current, chunk, &written, NULL) || written == 0) {
            result = -1;
            break;
        }

        current += written;
        remaining -= written;
    }

    if (!CloseHandle(file)) {
        result = -1;
    }

    return result;
}