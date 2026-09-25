#define _GNU_SOURCE
#include <errno.h>

int chave_e_transformacao_de_arquivos(void)
{
    errno = ENOTSUP;
    return -1;
}