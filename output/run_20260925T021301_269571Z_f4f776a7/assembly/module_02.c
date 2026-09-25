#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

 

typedef enum enumeracao_modo {
    ENUMERACAO_SIMULACAO = 0,
    ENUMERACAO_REMOVER = 1
} enumeracao_modo_t;

typedef enum enumeracao_estado_remocao {
    ENUMERACAO_NAO_APLICAVEL = 0,
    ENUMERACAO_REMocao_PLANEJADA = 1,
    ENUMERACAO_REMOVIDO = 2,
    ENUMERACAO_REMocao_FALHOU = 3
} enumeracao_estado_remocao_t;

typedef struct enumeracao_arquivo {
    char *caminho;
    char *extensao;
    int inventariado;
    enumeracao_estado_remocao_t estado_remocao;
    int erro_remocao;
} enumeracao_arquivo_t;

typedef struct enumeracao_erro {
    char *caminho;
    char *operacao;
    int codigo;
} enumeracao_erro_t;

typedef struct enumeracao_resultado {
    enumeracao_modo_t modo;
    size_t quantidade_arquivos;
    enumeracao_arquivo_t *arquivos;
    size_t quantidade_erros;
    enumeracao_erro_t *erros;
    int falha_alocacao;
} enumeracao_resultado_t;

typedef struct enumeracao_construtor {
    enumeracao_arquivo_t *arquivos;
    size_t quantidade_arquivos;
    size_t capacidade_arquivos;
    enumeracao_erro_t *erros;
    size_t quantidade_erros;
    size_t capacidade_erros;
    int falha_alocacao;
    int houve_erro;
    enumeracao_modo_t modo;
} enumeracao_construtor_t;

static const char *const enumeracao_extensoes_inventario[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg",
    ".png", ".db", ".backup", ".psd", ".zip", ".rar"
};

static const char *const enumeracao_extensoes_limpeza[] = {
    ".bak", ".backup", ".old"
};

static const char *const enumeracao_diretorios[] = {
    "~/Documentos_Teste",
    "~/Documentos",
    "~/Downloads",
    "~/Imagens",
    "/mnt"
};

static int enumeracao_somar_tamanho(size_t *total, size_t quantidade)
{
    if (quantidade > SIZE_MAX - *total) {
        return -1;
    }
    *total += quantidade;
    return 0;
}

static char *enumeracao_duplicar_intervalo(const char *inicio, size_t tamanho)
{
    char *copia;

    if (tamanho == SIZE_MAX) {
        return NULL;
    }

    copia = malloc(tamanho + 1);
    if (copia == NULL) {
        return NULL;
    }

    memcpy(copia, inicio, tamanho);
    copia[tamanho] = '\0';
    return copia;
}

static char *enumeracao_juntar_caminho(const char *diretorio,
                                       const char *nome)
{
    size_t tamanho_diretorio;
    size_t tamanho_nome;
    size_t separador;
    size_t total;
    char *caminho;

    tamanho_diretorio = strlen(diretorio);
    tamanho_nome = strlen(nome);
    separador = tamanho_diretorio != 0 &&
                diretorio[tamanho_diretorio - 1] != '/' ? 1 : 0;

    total = tamanho_diretorio;
    if (enumeracao_somar_tamanho(&total, separador) != 0 ||
        enumeracao_somar_tamanho(&total, tamanho_nome) != 0 ||
        enumeracao_somar_tamanho(&total, 1) != 0) {
        errno = ENOMEM;
        return NULL;
    }

    caminho = malloc(total);
    if (caminho == NULL) {
        return NULL;
    }

    memcpy(caminho, diretorio, tamanho_diretorio);
    if (separador != 0) {
        caminho[tamanho_diretorio] = '/';
    }
    memcpy(caminho + tamanho_diretorio + separador, nome, tamanho_nome);
    caminho[tamanho_diretorio + separador + tamanho_nome] = '\0';
    return caminho;
}

static char *enumeracao_resolver_raiz(const char *raiz)
{
    const char *home;
    const char *sufixo;
    size_t tamanho_home;
    size_t tamanho_sufixo;
    size_t separador;
    size_t total;
    char *resultado;

    if (raiz[0] != '~') {
        return strdup(raiz);
    }

    home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        errno = ENOENT;
        return NULL;
    }

    sufixo = raiz + 1;
    tamanho_home = strlen(home);
    tamanho_sufixo = strlen(sufixo);
    separador = tamanho_sufixo != 0 && sufixo[0] != '/' ? 1 : 0;

    total = tamanho_home;
    if (enumeracao_somar_tamanho(&total, separador) != 0 ||
        enumeracao_somar_tamanho(&total, tamanho_sufixo) != 0 ||
        enumeracao_somar_tamanho(&total, 1) != 0) {
        errno = ENOMEM;
        return NULL;
    }

    resultado = malloc(total);
    if (resultado == NULL) {
        return NULL;
    }

    memcpy(resultado, home, tamanho_home);
    if (separador != 0) {
        resultado[tamanho_home] = '/';
    }
    memcpy(resultado + tamanho_home + separador, sufixo, tamanho_sufixo);
    resultado[tamanho_home + separador + tamanho_sufixo] = '\0';
    return resultado;
}

static int enumeracao_extensao_corresponde(
    const char *extensao,
    const char *const *lista,
    size_t quantidade)
{
    size_t indice;

    for (indice = 0; indice < quantidade; ++indice) {
        if (strcasecmp(extensao, lista[indice]) == 0) {
            return 1;
        }
    }
    return 0;
}

static const char *enumeracao_extensao_final(const char *nome)
{
    const char *ponto;

    ponto = strrchr(nome, '.');
    if (ponto == NULL || ponto == nome) {
        return NULL;
    }
    return ponto;
}

static int enumeracao_reservar_arquivos(enumeracao_construtor_t *construtor)
{
    size_t nova_capacidade;
    enumeracao_arquivo_t *novo_vetor;

    if (construtor->quantidade_arquivos < construtor->capacidade_arquivos) {
        return 0;
    }

    nova_capacidade = construtor->capacidade_arquivos == 0
                          ? 16
                          : construtor->capacidade_arquivos * 2;
    if (nova_capacidade < construtor->capacidade_arquivos ||
        nova_capacidade > SIZE_MAX / sizeof(*novo_vetor)) {
        construtor->falha_alocacao = 1;
        errno = ENOMEM;
        return -1;
    }

    novo_vetor = realloc(construtor->arquivos,
                         nova_capacidade * sizeof(*novo_vetor));
    if (novo_vetor == NULL) {
        construtor->falha_alocacao = 1;
        return -1;
    }

    construtor->arquivos = novo_vetor;
    construtor->capacidade_arquivos = nova_capacidade;
    return 0;
}

static int enumeracao_reservar_erros(enumeracao_construtor_t *construtor)
{
    size_t nova_capacidade;
    enumeracao_erro_t *novo_vetor;

    if (construtor->quantidade_erros < construtor->capacidade_erros) {
        return 0;
    }

    nova_capacidade = construtor->capacidade_erros == 0
                          ? 8
                          : construtor->capacidade_erros * 2;
    if (nova_capacidade < construtor->capacidade_erros ||
        nova_capacidade > SIZE_MAX / sizeof(*novo_vetor)) {
        construtor->falha_alocacao = 1;
        errno = ENOMEM;
        return -1;
    }

    novo_vetor = realloc(construtor->erros,
                         nova_capacidade * sizeof(*novo_vetor));
    if (novo_vetor == NULL) {
        construtor->falha_alocacao = 1;
        return -1;
    }

    construtor->erros = novo_vetor;
    construtor->capacidade_erros = nova_capacidade;
    return 0;
}

static void enumeracao_registrar_erro(enumeracao_construtor_t *construtor,
                                      const char *caminho,
                                      const char *operacao,
                                      int codigo)
{
    enumeracao_erro_t *erro;
    char *caminho_copia;
    char *operacao_copia;

    construtor->houve_erro = 1;

    if (enumeracao_reservar_erros(construtor) != 0) {
        return;
    }

    caminho_copia = strdup(caminho != NULL ? caminho : "");
    operacao_copia = strdup(operacao != NULL ? operacao : "operação");
    if (caminho_copia == NULL || operacao_copia == NULL) {
        free(caminho_copia);
        free(operacao_copia);
        construtor->falha_alocacao = 1;
        return;
    }

    erro = &construtor->erros[construtor->quantidade_erros++];
    erro->caminho = caminho_copia;
    erro->operacao = operacao_copia;
    erro->codigo = codigo;
}

static int enumeracao_adicionar_arquivo(enumeracao_construtor_t *construtor,
                                        const char *caminho,
                                        const char *extensao,
                                        int inventariado,
                                        enumeracao_estado_remocao_t estado,
                                        size_t *indice_adicionado)
{
    enumeracao_arquivo_t *arquivo;
    char *caminho_copia;
    char *extensao_copia;

    if (enumeracao_reservar_arquivos(construtor) != 0) {
        return -1;
    }

    caminho_copia = strdup(caminho);
    extensao_copia = strdup(extensao);
    if (caminho_copia == NULL || extensao_copia == NULL) {
        free(caminho_copia);
        free(extensao_copia);
        construtor->falha_alocacao = 1;
        return -1;
    }

    *indice_adicionado = construtor->quantidade_arquivos;
    arquivo = &construtor->arquivos[construtor->quantidade_arquivos++];
    arquivo->caminho = caminho_copia;
    arquivo->extensao = extensao_copia;
    arquivo->inventariado = inventariado;
    arquivo->estado_remocao = estado;
    arquivo->erro_remocao = 0;
    return 0;
}

static void enumeracao_processar_arquivo(enumeracao_construtor_t *construtor,
                                         const char *caminho,
                                         const char *nome)
{
    const char *extensao;
    int inventariado;
    int elegivel_limpeza;
    size_t indice;
    struct stat estado_atual;
    int codigo;

    extensao = enumeracao_extensao_final(nome);
    if (extensao == NULL) {
        return;
    }

    inventariado = enumeracao_extensao_corresponde(
        extensao,
        enumeracao_extensoes_inventario,
        sizeof(enumeracao_extensoes_inventario) /
            sizeof(enumeracao_extensoes_inventario[0]));

    elegivel_limpeza = enumeracao_extensao_corresponde(
        extensao,
        enumeracao_extensoes_limpeza,
        sizeof(enumeracao_extensoes_limpeza) /
            sizeof(enumeracao_extensoes_limpeza[0]));

    if (!inventariado && !elegivel_limpeza) {
        return;
    }

    if (enumeracao_adicionar_arquivo(
            construtor,
            caminho,
            extensao,
            inventariado,
            elegivel_limpeza
                ? (construtor->modo == ENUMERACAO_SIMULACAO
                       ? ENUMERACAO_REMocao_PLANEJADA
                       : ENUMERACAO_REMocao_FALHOU)
                : ENUMERACAO_NAO_APLICAVEL,
            &indice) != 0) {
        return;
    }

    if (!elegivel_limpeza || construtor->modo == ENUMERACAO_SIMULACAO) {
        return;
    }

     
    if (lstat(caminho, &estado_atual) != 0) {
        codigo = errno;
        construtor->arquivos[indice].estado_remocao =
            ENUMERACAO_REMocao_FALHOU;
        construtor->arquivos[indice].erro_remocao = codigo;
        enumeracao_registrar_erro(construtor, caminho, "lstat antes de remove",
                                  codigo);
        return;
    }

    if (!S_ISREG(estado_atual.st_mode)) {
        codigo = EINVAL;
        construtor->arquivos[indice].estado_remocao =
            ENUMERACAO_REMocao_FALHOU;
        construtor->arquivos[indice].erro_remocao = codigo;
        enumeracao_registrar_erro(construtor, caminho,
                                  "verificação de arquivo regular", codigo);
        return;
    }

    if (remove(caminho) == 0) {
        construtor->arquivos[indice].estado_remocao = ENUMERACAO_REMOVIDO;
        return;
    }

    codigo = errno;
    construtor->arquivos[indice].estado_remocao = ENUMERACAO_REMocao_FALHOU;
    construtor->arquivos[indice].erro_remocao = codigo;
    enumeracao_registrar_erro(construtor, caminho, "remove", codigo);
}

static void enumeracao_percorrer_diretorio(
    enumeracao_construtor_t *construtor,
    const char *caminho_diretorio)
{
    DIR *diretorio;
    struct dirent *entrada;
    struct stat estado;
    char *caminho;
    int codigo;

    if (construtor->falha_alocacao) {
        return;
    }

    if (lstat(caminho_diretorio, &estado) != 0) {
        codigo = errno;
        enumeracao_registrar_erro(construtor, caminho_diretorio, "lstat",
                                  codigo);
        return;
    }

    if (!S_ISDIR(estado.st_mode)) {
        enumeracao_registrar_erro(construtor, caminho_diretorio,
                                  "verificação de diretório", ENOTDIR);
        return;
    }

    diretorio = opendir(caminho_diretorio);
    if (diretorio == NULL) {
        codigo = errno;
        enumeracao_registrar_erro(construtor, caminho_diretorio, "opendir",
                                  codigo);
        return;
    }

    for (;;) {
        errno = 0;
        entrada = readdir(diretorio);
        if (entrada == NULL) {
            codigo = errno;
            if (codigo != 0) {
                enumeracao_registrar_erro(construtor, caminho_diretorio,
                                          "readdir", codigo);
            }
            break;
        }

        if (strcmp(entrada->d_name, ".") == 0 ||
            strcmp(entrada->d_name, "..") == 0) {
            continue;
        }

        caminho = enumeracao_juntar_caminho(caminho_diretorio,
                                            entrada->d_name);
        if (caminho == NULL) {
            construtor->falha_alocacao = 1;
            enumeracao_registrar_erro(construtor, caminho_diretorio,
                                      "alocação de caminho", ENOMEM);
            break;
        }

        if (lstat(caminho, &estado) != 0) {
            codigo = errno;
            enumeracao_registrar_erro(construtor, caminho, "lstat", codigo);
            free(caminho);
            if (construtor->falha_alocacao) {
                break;
            }
            continue;
        }

        if (S_ISDIR(estado.st_mode)) {
            enumeracao_percorrer_diretorio(construtor, caminho);
        } else if (S_ISREG(estado.st_mode)) {
            enumeracao_processar_arquivo(construtor, caminho, entrada->d_name);
        }

        free(caminho);
        if (construtor->falha_alocacao) {
            break;
        }
    }

    if (closedir(diretorio) != 0) {
        codigo = errno;
        enumeracao_registrar_erro(construtor, caminho_diretorio, "closedir",
                                  codigo);
    }
}

static void enumeracao_liberar_construtor(
    enumeracao_construtor_t *construtor)
{
    size_t indice;

    for (indice = 0; indice < construtor->quantidade_arquivos; ++indice) {
        free(construtor->arquivos[indice].caminho);
        free(construtor->arquivos[indice].extensao);
    }
    for (indice = 0; indice < construtor->quantidade_erros; ++indice) {
        free(construtor->erros[indice].caminho);
        free(construtor->erros[indice].operacao);
    }
    free(construtor->arquivos);
    free(construtor->erros);
}

static enumeracao_resultado_t *enumeracao_finalizar(
    const enumeracao_construtor_t *construtor)
{
    size_t tamanho;
    size_t indice;
    size_t deslocamento;
    enumeracao_resultado_t *resultado;
    char *destino;

    tamanho = sizeof(*resultado);
    if (construtor->quantidade_arquivos >
        SIZE_MAX / sizeof(enumeracao_arquivo_t)) {
        return NULL;
    }
    if (enumeracao_somar_tamanho(
            &tamanho,
            construtor->quantidade_arquivos *
                sizeof(enumeracao_arquivo_t)) != 0) {
        return NULL;
    }
    if (construtor->quantidade_erros > SIZE_MAX / sizeof(enumeracao_erro_t)) {
        return NULL;
    }
    if (enumeracao_somar_tamanho(
            &tamanho,
            construtor->quantidade_erros * sizeof(enumeracao_erro_t)) != 0) {
        return NULL;
    }

    for (indice = 0; indice < construtor->quantidade_arquivos; ++indice) {
        if (enumeracao_somar_tamanho(
                &tamanho,
                strlen(construtor->arquivos[indice].caminho) + 1) != 0 ||
            enumeracao_somar_tamanho(
                &tamanho,
                strlen(construtor->arquivos[indice].extensao) + 1) != 0) {
            return NULL;
        }
    }
    for (indice = 0; indice < construtor->quantidade_erros; ++indice) {
        if (enumeracao_somar_tamanho(
                &tamanho,
                strlen(construtor->erros[indice].caminho) + 1) != 0 ||
            enumeracao_somar_tamanho(
                &tamanho,
                strlen(construtor->erros[indice].operacao) + 1) != 0) {
            return NULL;
        }
    }

    resultado = calloc(1, tamanho);
    if (resultado == NULL) {
        return NULL;
    }

    resultado->modo = construtor->modo;
    resultado->quantidade_arquivos = construtor->quantidade_arquivos;
    resultado->quantidade_erros = construtor->quantidade_erros;
    resultado->falha_alocacao = construtor->falha_alocacao;

    deslocamento = sizeof(*resultado);
    if (resultado->quantidade_arquivos != 0) {
        resultado->arquivos =
            (enumeracao_arquivo_t *)((char *)resultado + deslocamento);
        deslocamento += resultado->quantidade_arquivos *
                        sizeof(enumeracao_arquivo_t);
    }
    if (resultado->quantidade_erros != 0) {
        resultado->erros =
            (enumeracao_erro_t *)((char *)resultado + deslocamento);
        deslocamento += resultado->quantidade_erros *
                        sizeof(enumeracao_erro_t);
    }

    destino = (char *)resultado + deslocamento;
    for (indice = 0; indice < resultado->quantidade_arquivos; ++indice) {
        enumeracao_arquivo_t *saida = &resultado->arquivos[indice];
        const enumeracao_arquivo_t *origem =
            &construtor->arquivos[indice];
        size_t comprimento;

        *saida = *origem;
        comprimento = strlen(origem->caminho) + 1;
        saida->caminho = destino;
        memcpy(destino, origem->caminho, comprimento);
        destino += comprimento;

        comprimento = strlen(origem->extensao) + 1;
        saida->extensao = destino;
        memcpy(destino, origem->extensao, comprimento);
        destino += comprimento;
    }

    for (indice = 0; indice < resultado->quantidade_erros; ++indice) {
        enumeracao_erro_t *saida = &resultado->erros[indice];
        const enumeracao_erro_t *origem = &construtor->erros[indice];
        size_t comprimento;

        *saida = *origem;
        comprimento = strlen(origem->caminho) + 1;
        saida->caminho = destino;
        memcpy(destino, origem->caminho, comprimento);
        destino += comprimento;

        comprimento = strlen(origem->operacao) + 1;
        saida->operacao = destino;
        memcpy(destino, origem->operacao, comprimento);
        destino += comprimento;
    }

    return resultado;
}

 
int enumeracao_e_selecao_de_arquivos(enumeracao_modo_t modo,
                                     enumeracao_resultado_t **resultado)
{
    enumeracao_construtor_t construtor;
    size_t indice;
    char *raiz;
    int retorno;

    if (resultado == NULL) {
        errno = EINVAL;
        return -1;
    }

    *resultado = NULL;
    if (modo != ENUMERACAO_SIMULACAO && modo != ENUMERACAO_REMOVER) {
        errno = EINVAL;
        return -1;
    }

    memset(&construtor, 0, sizeof(construtor));
    construtor.modo = modo;

    for (indice = 0;
         indice < sizeof(enumeracao_diretorios) /
                      sizeof(enumeracao_diretorios[0]);
         ++indice) {
        raiz = enumeracao_resolver_raiz(enumeracao_diretorios[indice]);
        if (raiz == NULL) {
            int codigo = errno != 0 ? errno : ENOMEM;
            enumeracao_registrar_erro(&construtor,
                                      enumeracao_diretorios[indice],
                                      "resolver diretório", codigo);
            if (construtor.falha_alocacao) {
                break;
            }
            continue;
        }

        enumeracao_percorrer_diretorio(&construtor, raiz);
        free(raiz);

        if (construtor.falha_alocacao) {
            break;
        }
    }

    *resultado = enumeracao_finalizar(&construtor);
    if (*resultado == NULL) {
        enumeracao_liberar_construtor(&construtor);
        errno = ENOMEM;
        return -1;
    }

    retorno = (construtor.houve_erro || construtor.falha_alocacao) ? -1 : 0;
    enumeracao_liberar_construtor(&construtor);
    return retorno;
}