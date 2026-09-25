#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

/*
 * enumeracao_e_limpeza
 * ---------------------
 * Varredura recursiva de diretórios de usuário e volumes montados para
 * (a) capturar (registrar em stdout) arquivos com extensões "documentais"
 *     ou de imagem/backup, e (b) remover arquivos de backup obsoletos
 *     (.bak, .backup, .old). Arquivos .backup são capturados E removidos.
 *
 * Decisões principais:
 *  - lstat() em vez de stat(): não seguimos links simbólicos.
 *  - Symlinks são ignorados (nem diretório nem arquivo regular).
 *  - Diretórios são recursados; arquivos regulares são avaliados.
 *  - Erros (opendir/readdir/lstat/remove) são reportados em stderr e a
 *    varredura continua — nunca abortamos por EACCES/EPERM.
 *  - Caminhos são construídos com snprintf() sobre buffers PATH_MAX.
 *  - Comparações de extensão são case-insensitive.
 */

/* Extensões cujo caminho será apenas CAPTURADO (impresso em stdout). */
static const char *const g_ext_captura[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv",
    ".jpg",  ".png",  ".db",  ".backup", ".psd",
    ".zip",  ".rar",  NULL
};

/* Extensões cujo arquivo será REMOVIDO via remove(). */
static const char *const g_ext_remocao[] = {
    ".bak", ".backup", ".old", NULL
};

/* Compara string de forma case-insensitive. */
static int str_ieq(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

/* Verifica se 'ext' pertence a uma das listas terminadas por NULL. */
static int ext_pertence(const char *ext, const char *const *lista)
{
    if (ext == NULL || lista == NULL) {
        return 0;
    }
    for (size_t i = 0; lista[i] != NULL; i++) {
        if (str_ieq(ext, lista[i])) {
            return 1;
        }
    }
    return 0;
}

/*
 * Extrai a extensão a partir do ÚLTIMO '.' no nome base.
 * Retorna ponteiro para a substring ".ext" (incluindo o ponto) ou NULL
 * se não houver extensão válida (sem ponto, ou ponto inicial de dotfile).
 *
 * Oponente: não consideramos o '.' inicial de arquivos tipo ".bashrc"
 * como extensão — exigimos que haja pelo menos um caractere após '.' e
 * que o ponto não seja o primeiro caractere do nome.
 */
static const char *extrair_extensao(const char *nome)
{
    if (nome == NULL) {
        return NULL;
    }
    const char *ultimo_ponto = strrchr(nome, '.');
    if (ultimo_ponto == NULL) {
        return NULL;
    }
    /* '.' como primeiro caractere => dotfile, sem extensão "real". */
    if (ultimo_ponto == nome) {
        return NULL;
    }
    /* Ponto no final (ex.: "arquivo.") => sem extensão. */
    if (*(ultimo_ponto + 1) == '\0') {
        return NULL;
    }
    return ultimo_ponto;
}

/*
 * Caminha recursivamente em 'dir_path'.
 *  - Para cada entrada:
 *      * '.' e '..' ignoradas
 *      * lstat() (não stat) para não seguir links
 *      * diretório  -> recursão
 *      * symlink    -> ignorado
 *      * arquivo regular -> captura e/ou remoção
 */
static void varrer_recursivo(const char *dir_path)
{
    DIR *d = opendir(dir_path);
    if (d == NULL) {
        fprintf(stderr, "enumeracao_e_limpeza: opendir('%s') falhou: %s\n",
                dir_path, strerror(errno));
        return;
    }

    struct dirent *ent;
    errno = 0;
    while ((ent = readdir(d)) != NULL) {
        errno = 0;

        const char *nome = ent->d_name;
        if (strcmp(nome, ".") == 0 || strcmp(nome, "..") == 0) {
            continue;
        }

        /* Monta o caminho completo com snprintf para evitar overflow. */
        char caminho[PATH_MAX];
        int n = snprintf(caminho, sizeof(caminho), "%s/%s", dir_path, nome);
        if (n < 0 || (size_t)n >= sizeof(caminho)) {
            fprintf(stderr,
                    "enumeracao_e_limpeza: caminho truncado em '%s/%s'\n",
                    dir_path, nome);
            continue;
        }

        struct stat st;
        if (lstat(caminho, &st) != 0) {
            fprintf(stderr, "enumeracao_e_limpeza: lstat('%s') falhou: %s\n",
                    caminho, strerror(errno));
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            /* Ignoramos links simbólicos totalmente. */
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            varrer_recursivo(caminho);
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            /* Nem diretório, nem arquivo regular: ignoramos. */
            continue;
        }

        /* Arquivo regular: extrai extensão. */
        const char *ext = extrair_extensao(nome);

        /* Captura (impressão em stdout). Resultado é disponibilizado
         * nesta linha stdout; consumidor pode redirecionar/pipe. */
        if (ext != NULL && ext_pertence(ext, g_ext_captura)) {
            printf("%s\n", caminho);
            fflush(stdout);
        }

        /* Remoção via remove() — somente arquivos regulares cuja
         * extensão conste da lista de remoção. .backup dispara os
         * dois comportamentos: já foi capturado acima e agora é
         * removido aqui. */
        if (ext != NULL && ext_pertence(ext, g_ext_remocao)) {
            if (remove(caminho) != 0) {
                fprintf(stderr,
                        "enumeracao_e_limpeza: remove('%s') falhou: %s\n",
                        caminho, strerror(errno));
            }
        }
    }

    if (errno != 0) {
        fprintf(stderr, "enumeracao_e_limpeza: readdir('%s') falhou: %s\n",
                dir_path, strerror(errno));
    }

    if (closedir(d) != 0) {
        fprintf(stderr, "enumeracao_e_limpeza: closedir('%s') falhou: %s\n",
                dir_path, strerror(errno));
    }
}

/*
 * Expande "~" usando HOME; se não definido, cai em getpwuid(getuid())->pw_dir.
 * 'sub' é o caminho relativo ao home (ex.: "Documentos"). Monta o caminho
 * completo em 'out'. Retorna 0 em sucesso, -1 em falha.
 */
static int expandir_home(const char *sub, char *out, size_t out_sz)
{
    const char *home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        struct passwd *pw = getpwuid(getuid());
        if (pw != NULL && pw->pw_dir != NULL && pw->pw_dir[0] != '\0') {
            home = pw->pw_dir;
        }
    }
    if (home == NULL) {
        return -1;
    }
    int n = snprintf(out, out_sz, "%s/%s", home, sub);
    if (n < 0 || (size_t)n >= out_sz) {
        return -1;
    }
    return 0;
}

void enumeracao_e_limpeza(void)
{
    /* Diretórios relativos ao home do usuário atual. */
    static const char *const subs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        NULL
    };

    char caminho[PATH_MAX];

    for (size_t i = 0; subs[i] != NULL; i++) {
        if (expandir_home(subs[i], caminho, sizeof(caminho)) == 0) {
            varrer_recursivo(caminho);
        } else {
            fprintf(stderr,
                    "enumeracao_e_limpeza: falha ao expandir ~/%s\n",
                    subs[i]);
        }
    }

    /* Volume montado: caminho absoluto direto. */
    varrer_recursivo("/mnt");
}