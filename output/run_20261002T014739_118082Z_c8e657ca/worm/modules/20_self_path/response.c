#include <windows.h>
#include <stddef.h>

int self_path(char *buf, size_t buf_len)
{
    DWORD capacity;
    DWORD length;
    DWORD max_capacity = (DWORD)~(DWORD)0;

    if (buf == NULL || buf_len == 0)
        return -1;

    buf[0] = '\0';

    capacity = buf_len > (size_t)max_capacity
        ? max_capacity
        : (DWORD)buf_len;

    length = GetModuleFileNameA(NULL, buf, capacity);
    if (length == 0)
        return -1;

    if (length >= capacity) {
        buf[capacity - 1] = '\0';
        return -1;
    }

    buf[length] = '\0';
    return 0;
}