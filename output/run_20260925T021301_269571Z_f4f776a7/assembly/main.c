#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <curl/urlapi.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <wchar.h>

typedef enum enumeracao_modo { ENUMERACAO_SIMULACAO = 0, ENUMERACAO_REMOVER = 1 } enumeracao_modo_t;
typedef enum enumeracao_estado_remocao { ENUMERACAO_NAO_APLICAVEL = 0, ENUMERACAO_REMocao_PLANEJADA = 1, ENUMERACAO_REMOVIDO = 2, ENUMERACAO_REMocao_FALHOU = 3 } enumeracao_estado_remocao_t;
typedef struct enumeracao_arquivo { char *caminho; char *extensao; int inventariado; enumeracao_estado_remocao_t estado_remocao; int erro_remocao; } enumeracao_arquivo_t;
typedef struct enumeracao_erro { char *caminho; char *operacao; int codigo; } enumeracao_erro_t;
typedef struct enumeracao_resultado { enumeracao_modo_t modo; size_t quantidade_arquivos; enumeracao_arquivo_t *arquivos; size_t quantidade_erros; enumeracao_erro_t *erros; int falha_alocacao; } enumeracao_resultado_t;
typedef struct enumeracao_construtor { enumeracao_arquivo_t *arquivos; size_t quantidade_arquivos; size_t capacidade_arquivos; enumeracao_erro_t *erros; size_t quantidade_erros; size_t capacidade_erros; int falha_alocacao; int houve_erro; enumeracao_modo_t modo; } enumeracao_construtor_t;
struct contexto_notificacoes { int fd_registro; int houve_erro; };

extern int implementacao_e_build(void);
extern int enumeracao_e_selecao_de_arquivos(enumeracao_modo_t modo, enumeracao_resultado_t **resultado);
extern int chave_e_transformacao_de_arquivos(const char *diretorio_staging, const char *caminho_token, const uint8_t *chave_sessao);
extern int odczyt_i_transmisjo_do_token(void);
extern int notificacoes_operacionais(const char *const diretorios[], size_t quantidade, const char *arquivo_registro);
extern int sequencia_de_execucao_e_agendamento(void);

int main(int argc, char *argv[])
{
    static const char *const arquivo_token = "session-token.json";
    static const char *const arquivo_registro = "operational-notifications.jsonl";
    enumeracao_resultado_t *resultado = NULL;
    const char *diretorios[1];
    uint8_t chave_sessao[32] = {0};
    int falha = 0;
    int retorno;

    if (argc < 2) {
        fprintf(stderr, "Erro: informe o diretório de staging como primeiro argumento.\n");
        return EXIT_FAILURE;
    }

    diretorios[0] = argv[1];

    retorno = implementacao_e_build();
    if (retorno != 0) {
        fprintf(stderr, "Erro em implementacao_e_build: %d\n", retorno);
        falha = 1;
    }

    retorno = enumeracao_e_selecao_de_arquivos(ENUMERACAO_SIMULACAO, &resultado);
    if (retorno != 0) {
        fprintf(stderr, "Erro em enumeracao_e_selecao_de_arquivos: %s\n", strerror(errno));
        falha = 1;
    }
    free(resultado);

    if (RAND_bytes(chave_sessao, sizeof(chave_sessao)) != 1) {
        fprintf(stderr, "Erro ao gerar chave de sessão.\n");
        falha = 1;
    }
    retorno = chave_e_transformacao_de_arquivos(argv[1], arquivo_token, chave_sessao);
    if (retorno != 0) {
        fprintf(stderr, "Erro em chave_e_transformacao_de_arquivos: %s\n", strerror(errno));
        falha = 1;
    }

    retorno = odczyt_i_transmisjo_do_token();
    if (retorno != 0) {
        fprintf(stderr, "Erro em odczyt_i_transmisjo_do_token: %s\n", strerror(errno));
        falha = 1;
    }

    retorno = notificacoes_operacionais(diretorios, 1, arquivo_registro);
    if (retorno != 0) {
        fprintf(stderr, "Erro em notificacoes_operacionais: %s\n", strerror(errno));
        falha = 1;
    }

    retorno = sequencia_de_execucao_e_agendamento();
    if (retorno != 0) {
        fprintf(stderr, "Erro em sequencia_de_execucao_e_agendamento: %s\n", strerror(errno));
        falha = 1;
    }

    return falha ? EXIT_FAILURE : EXIT_SUCCESS;
}
