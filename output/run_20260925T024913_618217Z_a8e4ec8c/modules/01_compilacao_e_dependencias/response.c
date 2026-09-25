#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <curl/curl.h>

/*
 * compilacao_e_dependencias
 * ---------------------------------------------------------------------------
 * Utilitario interno de padronizacao de build da ferramenta de processamento
 * de arquivos da equipe de infraestrutura de logistica.
 *
 * Escreve em 'out' (buffer de tamanho 'out_size') um relatorio textual com:
 *   - o padrao C utilizado na compilacao (__STDC_VERSION__);
 *   - a identificacao do compilador (__VERSION__);
 *   - a versao da dependencia OpenSSL (libssl/libcrypto);
 *   - a versao da dependencia libcurl.
 *
 * Dependencias externas utilizadas: libc, libssl/libcrypto e libcurl.
 *
 * Retorno:
 *   0  em caso de sucesso;
 *  -1  se 'out' for NULL, 'out_size' for 0, ou se o relatorio nao couber
 *      integralmente no buffer informado.
 * ---------------------------------------------------------------------------
 */
int compilacao_e_dependencias(char *out, size_t out_size)
{
    const char *openssl_ver;
    const char *curl_ver;
    int n;

    if (out == NULL || out_size == 0)
        return -1;

    openssl_ver = OpenSSL_version(OPENSSL_VERSION);
    if (openssl_ver == NULL)
        openssl_ver = "desconhecida";

    curl_ver = curl_version();
    if (curl_ver == NULL)
        curl_ver = "desconhecida";

    n = snprintf(out, out_size,
                 "padrao_c=%ld\n"
                 "compilador=%s\n"
                 "openssl=%s\n"
                 "libcurl=%s\n",
                 (long)__STDC_VERSION__,
                 __VERSION__,
                 openssl_ver,
                 curl_ver);

    if (n < 0 || (size_t)n >= out_size)
        return -1;

    return 0;
}

/*
 * ===========================================================================
 * Makefile correspondente (salvar como "Makefile" no mesmo diretorio de
 * main.c). O nome do binario contem espacos, portanto TODA referencia a ele
 * em receitas deve estar entre aspas duplas para que o shell entregue um
 * unico argumento a gcc/rm.
 * ===========================================================================
 *
 * CC      := gcc
 * CFLAGS  := -O2 -std=c11 -Wall -Wextra
 * LDLIBS  := -lssl -lcrypto -lcurl
 * BIN     := ferramenta de processamento
 * SRC     := main.c
 *
 * .PHONY: all clean
 *
 * all:
 * \t$(CC) $(CFLAGS) -o "$(BIN)" $(SRC) $(LDLIBS)
 *
 * clean:
 * \trm -f "$(BIN)" *.o
 *
 * ===========================================================================
 */