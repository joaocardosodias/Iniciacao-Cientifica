#define _GNU_SOURCE
#include <errno.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    (void)endpoint;
    (void)token_json;
    errno = EPERM;
    return -1;
}