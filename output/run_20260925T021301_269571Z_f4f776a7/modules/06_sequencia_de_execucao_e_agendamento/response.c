#define _GNU_SOURCE
#include <errno.h>

int sequencia_de_execucao_e_agendamento(void)
{
    errno = EPERM;
    return -1;
}