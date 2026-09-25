#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <curl/urlapi.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
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

struct visited_directory { char *path; struct visited_directory *next; };
struct scan_context { struct visited_directory *visited; int had_error; };
struct notificacao_resultado { const char *diretorio; const char *raiz_autorizada; size_t arquivos_transformados; };
typedef struct { const char *data; size_t length; size_t position; } token_json_parser;
typedef struct { char *data; size_t length; size_t capacity; } token_response_buffer;

extern int plataforma_e_compilacao(void);
extern int chave_e_transformacao_de_arquivos(void);
extern int enumeracao_e_limpeza_de_arquivos(void);
extern int notificacoes_operacionais(const struct notificacao_resultado *resultados, size_t quantidade);
extern int token_e_transmissao_http(void);
extern int orquestracao_e_execucao_automatica(void);

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fputs("usage: output <input-path>\n", stderr);
        return EXIT_FAILURE;
    }

    struct notificacao_resultado resultado = { argv[1], argv[1], 0 };
    int failures = 0;

    failures += plataforma_e_compilacao() != 0;
    failures += chave_e_transformacao_de_arquivos() != 0;
    failures += enumeracao_e_limpeza_de_arquivos() != 0;
    failures += notificacoes_operacionais(&resultado, 1) != 0;
    failures += token_e_transmissao_http() != 0;
    failures += orquestracao_e_execucao_automatica() != 0;

    if (failures != 0) {
        fprintf(stderr, "%d operation(s) failed\n", failures);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
