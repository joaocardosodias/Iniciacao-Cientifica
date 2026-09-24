#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define CRONTAB_LIST_COMMAND "crontab -l"
#define CRONTAB_WRITE_COMMAND "crontab -"
#define CRONTAB_REBOOT_PREFIX "@reboot "

/*
 * Configuração: binary_path é o caminho do executável a agendar; directories
 * contém directory_count pastas a examinar. A função não percorre subpastas.
 *
 * Dependências: libc e o comando crontab disponível no PATH.
 * Retorna 0 se o crontab foi configurado e todas as pastas foram processadas
 * sem erros; retorna -1 se ocorreu qualquer erro. Após erros em uma pasta ou
 * arquivo, continua processando os demais.
 */
int crontab_file_cleanup_and_build(const char *binary_path,
                                   const char *const *directories,
                                   size_t directory_count)
{
    int result = 0;
    int cron_valid = 1;
    size_t binary_path_length = 0;
    char *cron_data = NULL;
    size_t cron_length = 0;
    size_t cron_capacity = 0;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    int reboot_entry_found = 0;
    int cron_read_ok = 1;

    if (binary_path == NULL || binary_path[0] == '\0' ||
        strchr(binary_path, '\n') != NULL ||
        strchr(binary_path, '\r') != NULL) {
        result = -1;
        cron_valid = 0;
    } else {
        binary_path_length = strlen(binary_path);
    }

    if (directory_count != 0 && directories == NULL) {
        result = -1;
    }

    if (cron_valid) {
        FILE *cron_input = popen(CRONTAB_LIST_COMMAND, "r");

        if (cron_input == NULL) {
            result = -1;
        } else {
            const size_t prefix_length = sizeof(CRONTAB_REBOOT_PREFIX) - 1;

            while ((line_length = getline(&line, &line_capacity, cron_input)) != -1) {
                size_t content_length = (size_t)line_length;

                if (content_length > 0 && line[content_length - 1] == '\n') {
                    --content_length;
                }
                if (content_length > 0 && line[content_length - 1] == '\r') {
                    --content_length;
                }

                if (content_length == prefix_length + binary_path_length &&
                    memcmp(line, CRONTAB_REBOOT_PREFIX, prefix_length) == 0 &&
                    memcmp(line + prefix_length, binary_path,
                           binary_path_length) == 0) {
                    reboot_entry_found = 1;
                }

                if ((size_t)line_length > SIZE_MAX - cron_length - 1) {
                    cron_read_ok = 0;
                    break;
                }

                if (cron_length + (size_t)line_length + 1 > cron_capacity) {
                    size_t needed = cron_length + (size_t)line_length + 1;
                    size_t new_capacity = cron_capacity == 0 ? 4096 : cron_capacity;

                    while (new_capacity < needed) {
                        if (new_capacity > SIZE_MAX / 2) {
                            new_capacity = needed;
                            break;
                        }
                        new_capacity *= 2;
                    }

                    char *new_data = realloc(cron_data, new_capacity);
                    if (new_data == NULL) {
                        cron_read_ok = 0;
                        break;
                    }
                    cron_data = new_data;
                    cron_capacity = new_capacity;
                }

                memcpy(cron_data + cron_length, line, (size_t)line_length);
                cron_length += (size_t)line_length;
            }

            if (ferror(cron_input)) {
                cron_read_ok = 0;
            }

            free(line);
            line = NULL;

            int read_status = pclose(cron_input);
            if (!cron_read_ok || read_status == -1 ||
                !WIFEXITED(read_status) || WEXITSTATUS(read_status) != 0) {
                result = -1;
            } else if (!reboot_entry_found) {
                FILE *cron_output = popen(CRONTAB_WRITE_COMMAND, "w");

                if (cron_output == NULL) {
                    result = -1;
                } else {
                    int write_ok = 1;

                    if (cron_length != 0 &&
                        fwrite(cron_data, 1, cron_length, cron_output) != cron_length) {
                        write_ok = 0;
                    }
                    if (cron_length != 0 && cron_data[cron_length - 1] != '\n' &&
                        fputc('\n', cron_output) == EOF) {
                        write_ok = 0;
                    }
                    if (fprintf(cron_output, "%s%s\n",
                                CRONTAB_REBOOT_PREFIX, binary_path) < 0) {
                        write_ok = 0;
                    }
                    if (fflush(cron_output) == EOF || ferror(cron_output)) {
                        write_ok = 0;
                    }

                    int write_status = pclose(cron_output);
                    if (!write_ok || write_status == -1 ||
                        !WIFEXITED(write_status) ||
                        WEXITSTATUS(write_status) != 0) {
                        result = -1;
                    }
                }
            }
        }
    }

    free(line);
    free(cron_data);

    if (directory_count != 0 && directories != NULL) {
        for (size_t i = 0; i < directory_count; ++i) {
            const char *directory = directories[i];

            if (directory == NULL || directory[0] == '\0') {
                result = -1;
                continue;
            }

            DIR *dir = opendir(directory);
            if (dir == NULL) {
                result = -1;
                continue;
            }

            for (;;) {
                errno = 0;
                struct dirent *entry = readdir(dir);
                if (entry == NULL) {
                    if (errno != 0) {
                        result = -1;
                    }
                    break;
                }

                const char *name = entry->d_name;
                size_t name_length = strlen(name);
                int has_obsolete_extension =
                    (name_length >= 4 &&
                     strcmp(name + name_length - 4, ".bak") == 0) ||
                    (name_length >= 7 &&
                     strcmp(name + name_length - 7, ".backup") == 0) ||
                    (name_length >= 4 &&
                     strcmp(name + name_length - 4, ".old") == 0);

                if (!has_obsolete_extension) {
                    continue;
                }

                size_t directory_length = strlen(directory);
                int needs_separator =
                    directory_length > 0 &&
                    directory[directory_length - 1] != '/';

                if (name_length > SIZE_MAX - 2 ||
                    directory_length > SIZE_MAX - name_length - 2) {
                    result = -1;
                    continue;
                }

                size_t path_length = directory_length + name_length +
                                     (needs_separator ? 1 : 0);
                if (path_length == SIZE_MAX) {
                    result = -1;
                    continue;
                }

                char *path = malloc(path_length + 1);
                if (path == NULL) {
                    result = -1;
                    continue;
                }

                memcpy(path, directory, directory_length);
                size_t offset = directory_length;
                if (needs_separator) {
                    path[offset++] = '/';
                }
                memcpy(path + offset, name, name_length);
                path[offset + name_length] = '\0';

                struct stat file_status;
                if (lstat(path, &file_status) != 0) {
                    result = -1;
                } else if (S_ISREG(file_status.st_mode) && remove(path) != 0) {
                    result = -1;
                }

                free(path);
            }

            if (closedir(dir) != 0) {
                result = -1;
            }
        }
    }

    return result;
}