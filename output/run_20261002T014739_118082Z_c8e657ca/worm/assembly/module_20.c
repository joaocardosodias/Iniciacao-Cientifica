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