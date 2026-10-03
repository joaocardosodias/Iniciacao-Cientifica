#include <windows.h>
#include <stddef.h>

int self_path(char *buf, size_t buf_len)
{
    DWORD capacity;
    DWORD length;

    if (buf == NULL || buf_len == 0)
        return -1;

    capacity = buf_len > (size_t)(DWORD)-1 ? (DWORD)-1 : (DWORD)buf_len;
    if (capacity == 0)
        return -1;

    buf[0] = '\0';
    length = GetModuleFileNameA(NULL, buf, capacity);
    if (length == 0 || length >= capacity) {
        buf[0] = '\0';
        return -1;
    }

    buf[length] = '\0';
    return 0;
}