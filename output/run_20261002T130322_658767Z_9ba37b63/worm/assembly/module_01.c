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
#include <bcrypt.h>
#include <limits.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    unsigned char *p = out;

    if (len != 0 && out == NULL)
        return -1;

    while (len != 0) {
        ULONG chunk = len > (size_t)ULONG_MAX ? ULONG_MAX : (ULONG)len;
        NTSTATUS status = BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (status < 0)
            return -1;

        p += chunk;
        len -= chunk;
    }

    return 0;
}