#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void
set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list args;

    if (error == NULL || error_size == 0)
        return;

    va_start(args, format);
    vsnprintf(error, error_size, format, args);
    va_end(args);
}

static int
is_safe_executable_name(const char *name)
{
    const unsigned char *p;

    if (name == NULL || name[0] == '\0' ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;

    for (p = (const unsigned char *)name; *p != '\0'; ++p) {
        if (!((*p >= 'a' && *p <= 'z') ||
              (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }

    return 1;
}

static int
is_safe_source_path(const char *path)
{
    const unsigned char *p;
    const char *component;
    size_t length;

    if (path == NULL || path[0] == '\0' || path[0] == '/')
        return 0;

    length = strlen(path);
    if (length < 3 || strcmp(path + length - 2, ".c") != 0)
        return 0;

    component = path;
    for (p = (const unsigned char *)path; ; ++p) {
        if (*p == '/' || *p == '\0') {
            size_t component_length = (size_t)((const char *)p - component);

            if (component_length == 0 ||
                (component_length == 1 && component[0] == '.') ||
                (component_length == 2 &&
                 component[0] == '.' && component[1] == '.'))
                return 0;

            if (*p == '\0')
                break;

            component = (const char *)p + 1;
        } else if (!((*p >= 'a' && *p <= 'z') ||
                     (*p >= 'A' && *p <= 'Z') ||
                     (*p >= '0' && *p <= '9') ||
                     *p == '_' || *p == '-' || *p == '.')) {
            return 0;
        }
    }

    return 1;
}

/*
 * Assinatura:
 * int build_project(const char *destination_dir,
 *                   const char *executable_name,
 *                   const char *const source_files[],
 *                   size_t source_count,
 *                   char *error,
 *                   size_t error_size);
 *
 * Cria destination_dir/Makefile. Retorna 0 em caso de sucesso e -1 em caso
 * de falha; quando fornecido, error recebe uma descrição da falha.
 *
 * Exemplo de uso:
 *   const char *sources[] = {"main.c"};
 *   char error[256];
 *   if (build_project(".", "utilidade", sources, 1,
 *                     error, sizeof error) != 0)
 *       fprintf(stderr, "%s\n", error);
 *
 * Para esse exemplo, o Makefile gerado é:
 *
 * .DEFAULT_GOAL := all
 * CC ?= cc
 * CFLAGS ?= -std=c11 -Wall -Wextra -O2
 * LDFLAGS ?=
 * LDLIBS ?= -lcurl -lssl -lcrypto
 *
 * TARGET ?= utilidade
 * SOURCES ?= main.c
 * OBJECTS := $(SOURCES:.c=.o)
 *
 * .PHONY: all clean
 *
 * all: $(TARGET)
 *
 * $(TARGET): $(OBJECTS)
 *	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
 *
 * %.o: %.c
 *	$(CC) $(CFLAGS) -c -o $@ $<
 *
 * clean:
 *	$(RM) $(TARGET) $(OBJECTS)
 */
int
build_project(const char *destination_dir,
              const char *executable_name,
              const char *const source_files[],
              size_t source_count,
              char *error,
              size_t error_size)
{
    struct stat directory_status;
    size_t directory_length;
    size_t makefile_length;
    size_t i;
    int separator;
    char *makefile_path;
    FILE *makefile;

    if (error != NULL && error_size > 0)
        error[0] = '\0';

    if (destination_dir == NULL || destination_dir[0] == '\0') {
        set_error(error, error_size, "O diretório de destino é obrigatório.");
        return -1;
    }

    if (!is_safe_executable_name(executable_name)) {
        set_error(error, error_size,
                  "Nome de executável inválido; use apenas letras, dígitos, '.', '_' ou '-'.");
        return -1;
    }

    if (source_files == NULL || source_count == 0) {
        set_error(error, error_size, "É necessário informar ao menos um arquivo-fonte.");
        return -1;
    }

    for (i = 0; i < source_count; ++i) {
        size_t j;

        if (!is_safe_source_path(source_files[i])) {
            set_error(error, error_size,
                      "Caminho de fonte inválido na posição %zu; informe um caminho relativo seguro terminado em .c.",
                      i);
            return -1;
        }

        for (j = 0; j < i; ++j) {
            if (strcmp(source_files[i], source_files[j]) == 0) {
                set_error(error, error_size,
                          "O arquivo-fonte '%s' foi informado mais de uma vez.",
                          source_files[i]);
                return -1;
            }
        }
    }

    if (stat(destination_dir, &directory_status) != 0) {
        int saved_errno = errno;
        set_error(error, error_size, "Não foi possível acessar o diretório '%s': %s",
                  destination_dir, strerror(saved_errno));
        return -1;
    }

    if (!S_ISDIR(directory_status.st_mode)) {
        set_error(error, error_size, "'%s' não é um diretório.", destination_dir);
        return -1;
    }

    directory_length = strlen(destination_dir);
    separator = destination_dir[directory_length - 1] != '/';

    if (directory_length > (size_t)-1 - (size_t)separator - sizeof("Makefile")) {
        set_error(error, error_size, "O caminho do Makefile é longo demais.");
        return -1;
    }

    makefile_length = directory_length + (size_t)separator + sizeof("Makefile");
    makefile_path = malloc(makefile_length);
    if (makefile_path == NULL) {
        set_error(error, error_size, "Memória insuficiente para criar o caminho do Makefile.");
        return -1;
    }

    snprintf(makefile_path, makefile_length, "%s%sMakefile",
             destination_dir, separator ? "/" : "");

    makefile = fopen(makefile_path, "w");
    if (makefile == NULL) {
        int saved_errno = errno;
        set_error(error, error_size, "Não foi possível criar '%s': %s",
                  makefile_path, strerror(saved_errno));
        free(makefile_path);
        return -1;
    }

    if (fprintf(makefile,
                ".DEFAULT_GOAL := all\n"
                "CC ?= cc\n"
                "CFLAGS ?= -std=c11 -Wall -Wextra -O2\n"
                "LDFLAGS ?=\n"
                "LDLIBS ?= -lcurl -lssl -lcrypto\n"
                "\n"
                "TARGET ?= %s\n"
                "SOURCES ?=",
                executable_name) < 0)
        goto write_error;

    for (i = 0; i < source_count; ++i) {
        if (fprintf(makefile, "%s%s", i == 0 ? " " : " ",
                    source_files[i]) < 0)
            goto write_error;
    }

    if (fputs("\n"
              "OBJECTS := $(SOURCES:.c=.o)\n"
              "\n"
              ".PHONY: all clean\n"
              "\n"
              "all: $(TARGET)\n"
              "\n"
              "$(TARGET): $(OBJECTS)\n"
              "\t$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)\n"
              "\n"
              "%.o: %.c\n"
              "\t$(CC) $(CFLAGS) -c -o $@ $<\n"
              "\n"
              "clean:\n"
              "\t$(RM) $(TARGET) $(OBJECTS)\n",
              makefile) == EOF)
        goto write_error;

    if (fclose(makefile) != 0) {
        int saved_errno = errno != 0 ? errno : EIO;
        set_error(error, error_size, "Falha ao finalizar '%s': %s",
                  makefile_path, strerror(saved_errno));
        free(makefile_path);
        return -1;
    }

    free(makefile_path);
    return 0;

write_error:
    {
        int saved_errno = errno != 0 ? errno : EIO;
        fclose(makefile);
        set_error(error, error_size, "Falha ao escrever '%s': %s",
                  makefile_path, strerror(saved_errno));
        free(makefile_path);
        return -1;
    }
}

int
main(int argc, char **argv)
{
    const char **source_files;
    size_t source_count;
    size_t i;
    char error[512];
    int result;

    if (argc < 4) {
        fprintf(stderr,
                "Uso: %s DIRETORIO NOME_EXECUTAVEL FONTE.c [FONTE.c ...]\n",
                argv[0]);
        fprintf(stderr,
                "Exemplo: %s . utilidade main.c\n",
                argv[0]);
        return 2;
    }

    source_count = (size_t)(argc - 3);
    source_files = malloc(source_count * sizeof(*source_files));
    if (source_files == NULL) {
        fprintf(stderr, "Memória insuficiente para armazenar os arquivos-fonte.\n");
        return 1;
    }

    for (i = 0; i < source_count; ++i)
        source_files[i] = argv[i + 3];

    result = build_project(argv[1], argv[2], source_files, source_count,
                           error, sizeof error);
    free(source_files);

    if (result != 0) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }

    printf("Makefile criado em '%s%sMakefile'.\n",
           argv[1],
           argv[1][strlen(argv[1]) - 1] == '/' ? "" : "/");
    return 0;
}