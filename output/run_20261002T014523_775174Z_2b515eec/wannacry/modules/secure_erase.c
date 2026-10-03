#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER size;
    LARGE_INTEGER remaining;
    unsigned char zeros[65536] = {0};
    BOOL ok;
    int result;

    if (path == NULL)
        return -1;

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    result = -1;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0)
        goto cleanup;

    remaining = size;
    while (remaining.QuadPart > 0) {
        DWORD amount = remaining.QuadPart > (LONGLONG)sizeof(zeros)
                           ? (DWORD)sizeof(zeros)
                           : (DWORD)remaining.QuadPart;
        DWORD written = 0;

        ok = WriteFile(file, zeros, amount, &written, NULL);
        if (!ok || written == 0 || written > amount)
            goto cleanup;

        remaining.QuadPart -= written;
    }

    if (!FlushFileBuffers(file))
        goto cleanup;

    if (!CloseHandle(file))
        return -1;
    file = INVALID_HANDLE_VALUE;

    return DeleteFileA(path) ? 0 : -1;

cleanup:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    return result;
}