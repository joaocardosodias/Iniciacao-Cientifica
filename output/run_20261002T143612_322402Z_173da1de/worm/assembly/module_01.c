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
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    size_t offset = 0;
    const size_t max_chunk = (size_t)(ULONG)-1;

    if (len != 0 && out == NULL)
        return -1;

    while (offset < len) {
        size_t remaining = len - offset;
        ULONG chunk = (ULONG)(remaining > max_chunk ? max_chunk : remaining);
        NTSTATUS status = BCryptGenRandom(
            NULL,
            out + offset,
            chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        if (status < 0)
            return -1;

        offset += chunk;
    }

    return 0;
}