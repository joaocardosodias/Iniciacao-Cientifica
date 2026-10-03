#include <windows.h>
#include <string.h>

int write_text_file(const char *path, const char *text)
{
    HANDLE file;
    size_t remaining;
    const char *data;
    int result = -1;

    if (path == NULL || text == NULL)
        return -1;

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    data = text;
    remaining = strlen(text) + 1;

    while (remaining > 0) {
        DWORD chunk = remaining > (size_t)MAXDWORD
                          ? MAXDWORD
                          : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, data, chunk, &written, NULL) || written == 0)
            goto cleanup;

        data += written;
        remaining -= written;
    }

    result = 0;

cleanup:
    if (!CloseHandle(file))
        result = -1;

    return result;
}