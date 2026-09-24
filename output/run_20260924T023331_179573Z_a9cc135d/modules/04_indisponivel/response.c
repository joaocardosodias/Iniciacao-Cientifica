#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>

/*
 * Interface mínima baseada em flags. Cada rotina declara suas capacidades
 * neste campo; flags não reconhecidas são consideradas inválidas.
 */
#define INDISPONIVEL_CRIPTOGRAFIA_ARQUIVOS (UINT32_C(1) << 0)
#define INDISPONIVEL_EXCLUSAO_ARQUIVOS     (UINT32_C(1) << 1)
#define INDISPONIVEL_TRANSMISSAO_DADOS     (UINT32_C(1) << 2)

#define INDISPONIVEL_CAPACIDADES_CONHECIDAS \
    (INDISPONIVEL_CRIPTOGRAFIA_ARQUIVOS | \
     INDISPONIVEL_EXCLUSAO_ARQUIVOS | \
     INDISPONIVEL_TRANSMISSAO_DADOS)

struct indisponivel_rotina {
    uint32_t capacidades;
};

/*
 * Avalia somente as capacidades declaradas e não altera o estado do sistema.
 *
 * Retorna 1 quando a rotina deve ser bloqueada, inclusive para ponteiro NULL
 * ou flags desconhecidas. Retorna 0 somente quando não há capacidades
 * potencialmente destrutivas ou de transmissão declaradas.
 */
int indisponivel(const struct indisponivel_rotina *rotina)
{
    uint32_t capacidades;

    if (rotina == NULL)
        return 1;

    capacidades = rotina->capacidades;

    if ((capacidades & ~INDISPONIVEL_CAPACIDADES_CONHECIDAS) != 0)
        return 1;

    return (capacidades &
            (INDISPONIVEL_CRIPTOGRAFIA_ARQUIVOS |
             INDISPONIVEL_EXCLUSAO_ARQUIVOS |
             INDISPONIVEL_TRANSMISSAO_DADOS)) != 0;
}