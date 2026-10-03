#include "config.h"
#include <stdio.h>

int execute_eternalblue(const char *ip, int port, const char *payload_path)
{
    (void)ip;
    (void)port;
    (void)payload_path;
    printf("execute_eternalblue: operation refused.\n");
    return -1;
}