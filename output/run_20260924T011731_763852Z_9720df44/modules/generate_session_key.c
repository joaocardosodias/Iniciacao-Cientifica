#define _GNU_SOURCE
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>

int generate_session_key(unsigned char key[32])
{
    if (key == NULL) {
        return 0;
    }

    /* A chave só é válida se o OpenSSL gerar os 32 bytes com sucesso. */
    if (RAND_bytes(key, 32) != 1) {
        OPENSSL_cleanse(key, 32);
        return 0;
    }

    return 1;
}

/*
 * Chamada única durante a inicialização. O chamador deve interromper a
 * inicialização se esta função retornar -1.
 */
int initialize_service(unsigned char session_key[32])
{
    if (!generate_session_key(session_key)) {
        fputs("Falha ao gerar a chave de sessão.\n", stderr);
        return -1;
    }

    return 0;
}