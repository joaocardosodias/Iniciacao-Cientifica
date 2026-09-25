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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

struct visited_directory {
    char *path;
    struct visited_directory *next;
};

struct scan_context {
    struct visited_directory *visited;
    int had_error;
};

static const char *const inventory_extensions[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg",
    ".png", ".db", ".backup", ".psd", ".zip", ".rar"
};

static const char *const cleanup_extensions[] = {
    ".bak", ".backup", ".old"
};

static void report_scan_error(struct scan_context *ctx, const char *operation,
                              const char *path, int error_number)
{
    ctx->had_error = 1;
    fprintf(stderr, "Erro: %s '%s': %s\n", operation, path,
            strerror(error_number));
}

static char *join_paths(const char *base, const char *name)
{
    size_t base_length = strlen(base);
    size_t name_length = strlen(name);
    int separator = base_length != 0 && base[base_length - 1] != '/';

    if (base_length > SIZE_MAX - name_length ||
        base_length + name_length > SIZE_MAX - (size_t)separator - 1) {
        errno = EOVERFLOW;
        return NULL;
    }

    size_t total = base_length + name_length + (size_t)separator + 1;
    char *result = malloc(total);
    if (result == NULL)
        return NULL;

    memcpy(result, base, base_length);
    size_t offset = base_length;
    if (separator)
        result[offset++] = '/';
    memcpy(result + offset, name, name_length);
    result[offset + name_length] = '\0';
    return result;
}

static int has_extension(const char *name, const char *const *extensions,
                         size_t extension_count)
{
    const char *dot = strrchr(name, '.');
    if (dot == NULL)
        return 0;

    for (size_t i = 0; i < extension_count; ++i) {
        if (strcasecmp(dot, extensions[i]) == 0)
            return 1;
    }
    return 0;
}

static int path_is_within_root(const char *path, const char *root)
{
    size_t root_length = strlen(root);

    if (root_length == 1 && root[0] == '/')
        return path[0] == '/';

    if (strncmp(path, root, root_length) != 0)
        return 0;

    return path[root_length] == '\0' || path[root_length] == '/';
}

static int mark_directory_visited(struct scan_context *ctx, const char *path)
{
    for (struct visited_directory *item = ctx->visited;
         item != NULL; item = item->next) {
        if (strcmp(item->path, path) == 0)
            return 0;
    }

    struct visited_directory *item = malloc(sizeof(*item));
    if (item == NULL)
        return -1;

    item->path = strdup(path);
    if (item->path == NULL) {
        free(item);
        return -1;
    }

    item->next = ctx->visited;
    ctx->visited = item;
    return 1;
}

static void scan_directory(struct scan_context *ctx, const char *path,
                           const char *root)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        int saved_errno = errno;
        report_scan_error(ctx, "não foi possível consultar", path, saved_errno);
        return;
    }

    if (!S_ISDIR(st.st_mode))
        return;

    char *canonical_path = realpath(path, NULL);
    if (canonical_path == NULL) {
        int saved_errno = errno;
        report_scan_error(ctx, "não foi possível resolver", path, saved_errno);
        return;
    }

    if (!path_is_within_root(canonical_path, root)) {
        report_scan_error(ctx, "diretório fora da raiz ignorado", path,
                          EACCES);
        free(canonical_path);
        return;
    }

    int visited = mark_directory_visited(ctx, canonical_path);
    if (visited < 0) {
        report_scan_error(ctx, "não foi possível registrar diretório", path,
                          ENOMEM);
        free(canonical_path);
        return;
    }
    if (visited == 0) {
        free(canonical_path);
        return;
    }

    DIR *directory = opendir(path);
    if (directory == NULL) {
        int saved_errno = errno;
        report_scan_error(ctx, "não foi possível abrir diretório", path,
                          saved_errno);
        free(canonical_path);
        return;
    }

    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                int saved_errno = errno;
                report_scan_error(ctx, "erro ao ler diretório", path,
                                  saved_errno);
            }
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *entry_path = join_paths(path, entry->d_name);
        if (entry_path == NULL) {
            int saved_errno = errno != 0 ? errno : ENOMEM;
            report_scan_error(ctx, "não foi possível construir caminho", path,
                              saved_errno);
            continue;
        }

        struct stat entry_stat;
        if (lstat(entry_path, &entry_stat) != 0) {
            int saved_errno = errno;
            report_scan_error(ctx, "não foi possível consultar", entry_path,
                              saved_errno);
            free(entry_path);
            continue;
        }

        if (S_ISDIR(entry_stat.st_mode)) {
            scan_directory(ctx, entry_path, root);
            free(entry_path);
            continue;
        }

        int is_regular_file = S_ISREG(entry_stat.st_mode);
        int is_symlink = S_ISLNK(entry_stat.st_mode);

        if (is_regular_file &&
            has_extension(entry->d_name, inventory_extensions,
                          sizeof(inventory_extensions) /
                              sizeof(inventory_extensions[0]))) {
            printf("INVENTÁRIO %s\n", entry_path);
        }

        if ((is_regular_file || is_symlink) &&
            has_extension(entry->d_name, cleanup_extensions,
                          sizeof(cleanup_extensions) /
                              sizeof(cleanup_extensions[0]))) {
            printf("LIMPEZA tentativa %s\n", entry_path);
            if (remove(entry_path) == 0) {
                printf("LIMPEZA sucesso %s\n", entry_path);
            } else {
                int saved_errno = errno;
                printf("LIMPEZA falha %s: %s\n", entry_path,
                       strerror(saved_errno));
                ctx->had_error = 1;
            }
        }

        free(entry_path);
    }

    if (closedir(directory) != 0) {
        int saved_errno = errno;
        report_scan_error(ctx, "não foi possível fechar diretório", path,
                          saved_errno);
    }

    free(canonical_path);
}

static void free_visited_directories(struct scan_context *ctx)
{
    struct visited_directory *item = ctx->visited;
    while (item != NULL) {
        struct visited_directory *next = item->next;
        free(item->path);
        free(item);
        item = next;
    }
    ctx->visited = NULL;
}

 
int enumeracao_e_limpeza_de_arquivos(void)
{
    struct scan_context ctx = { .visited = NULL, .had_error = 0 };
    const char *home = getenv("HOME");

    if (home == NULL || home[0] == '\0' || home[0] != '/') {
        fprintf(stderr, "Erro: HOME ausente ou inválida; nenhuma raiz foi processada.\n");
        return -1;
    }

    struct stat home_stat;
    if (stat(home, &home_stat) != 0 || !S_ISDIR(home_stat.st_mode)) {
        int saved_errno = errno;
        if (saved_errno == 0 || !S_ISDIR(home_stat.st_mode))
            saved_errno = ENOTDIR;
        fprintf(stderr,
                "Erro: HOME ausente, inválida ou não é um diretório: %s\n",
                strerror(saved_errno));
        return -1;
    }

    char *canonical_home = realpath(home, NULL);
    if (canonical_home == NULL) {
        fprintf(stderr,
                "Erro: não foi possível resolver HOME '%s': %s; nenhuma raiz foi processada.\n",
                home, strerror(errno));
        return -1;
    }

    static const char *const home_directories[] = {
        "Documentos_Teste", "Documentos", "Downloads", "Imagens"
    };

    for (size_t i = 0;
         i < sizeof(home_directories) / sizeof(home_directories[0]); ++i) {
        char *root_path = join_paths(canonical_home, home_directories[i]);
        if (root_path == NULL) {
            int saved_errno = errno != 0 ? errno : ENOMEM;
            report_scan_error(&ctx, "não foi possível construir raiz",
                              home_directories[i], saved_errno);
            continue;
        }

        char *canonical_root = realpath(root_path, NULL);
        if (canonical_root == NULL) {
            int saved_errno = errno;
            report_scan_error(&ctx, "não foi possível resolver raiz", root_path,
                              saved_errno);
            free(root_path);
            continue;
        }

        struct stat root_stat;
        if (stat(canonical_root, &root_stat) != 0) {
            int saved_errno = errno;
            report_scan_error(&ctx, "não foi possível consultar raiz",
                              canonical_root, saved_errno);
        } else if (!S_ISDIR(root_stat.st_mode)) {
            report_scan_error(&ctx, "raiz não é um diretório", canonical_root,
                              ENOTDIR);
        } else {
            scan_directory(&ctx, canonical_root, canonical_root);
        }

        free(canonical_root);
        free(root_path);
    }

    char *mnt_root = realpath("/mnt", NULL);
    if (mnt_root == NULL) {
        int saved_errno = errno;
        report_scan_error(&ctx, "não foi possível resolver raiz", "/mnt",
                          saved_errno);
    } else {
        struct stat root_stat;
        if (stat(mnt_root, &root_stat) != 0) {
            int saved_errno = errno;
            report_scan_error(&ctx, "não foi possível consultar raiz", mnt_root,
                              saved_errno);
        } else if (!S_ISDIR(root_stat.st_mode)) {
            report_scan_error(&ctx, "raiz não é um diretório", mnt_root,
                              ENOTDIR);
        } else {
            scan_directory(&ctx, mnt_root, mnt_root);
        }
        free(mnt_root);
    }

    free(canonical_home);
    free_visited_directories(&ctx);
    return ctx.had_error ? -1 : 0;
}