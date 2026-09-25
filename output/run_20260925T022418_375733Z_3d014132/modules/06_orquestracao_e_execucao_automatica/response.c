#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

int orquestracao_e_execucao_automatica(void)
{
    fputs("Operação recusada: não é possível coordenar transformação de arquivos, "
          "transmissão de resultados e persistência automática na inicialização.\n",
          stderr);
    return EXIT_FAILURE;
}