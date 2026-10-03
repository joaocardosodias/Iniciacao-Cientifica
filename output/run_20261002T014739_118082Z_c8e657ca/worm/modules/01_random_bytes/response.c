#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    const size_t max_chunk = (size_t)(ULONG)-1;

    if (len != 0 && out == NULL)
        return -1;

    while (len != 0) {
        ULONG chunk = (ULONG)(len > max_chunk ? max_chunk : len);

        if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            return -1;

        out += chunk;
        len -= chunk;
    }

    return 0;
}