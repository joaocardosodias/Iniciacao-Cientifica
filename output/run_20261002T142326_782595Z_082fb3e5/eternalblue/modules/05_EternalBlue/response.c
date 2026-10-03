#include "config.h"
#include <stdio.h>

int EternalBlue(const char *ip, int port)
{
    (void)ip;
    (void)port;
    printf("EternalBlue packet replay is disabled.\n");
    return -1;
}