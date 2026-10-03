#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (len != 0 && out == NULL) {
        return -1;
    }

    while (len != 0) {
        ULONG chunk = len > (size_t)0xFFFFFFFFUL
            ? (ULONG)0xFFFFFFFFUL
            : (ULONG)len;

        if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            return -1;
        }

        out += chunk;
        len -= chunk;
    }

    return 0;
}